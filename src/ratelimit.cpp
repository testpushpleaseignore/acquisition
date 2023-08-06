/*
	Copyright 2023 Tom Holz

	This file is part of Acquisition.

	Acquisition is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Acquisition is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Acquisition.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "ratelimit.h"

#include <stdexcept>
#include <boost/circular_buffer.hpp>

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
#include <QUrl>
#include <QDir>
#include <QFile>
#include <QCoreApplication>

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"

#include "mainwindow.h"
#include "itemsmanagerworker.h"
#include "QsLog.h"

using namespace RateLimit;

//=========================================================================================
// INTERNALS
//=========================================================================================

// Everything used internally by the rate limiter is defined in an anoynmous
// namespace to make it inaccesible to the rest of the application. This is 
// to avoid bugs and accidental coupling.

namespace {

	// This HTTP status code means there was a rate limit violation.
	const int RATE_LIMIT_VIOLATION_STATUS = 429;

	// A delay added to requests to make sure we don't get a violation.
	const int VIOLATION_AVOIDANCE_MSEC = 50;

	// When there is a violation, add this much time to how long we
	// wait just to make sure we don't trigger another violation.
	const int EXTRA_RATE_VIOLATION_MSEC = 250;

	// Return the name of the policy from a network reply
	QByteArray GetPolicy(QNetworkReply* const reply) {
		assert(reply->hasRawHeader("X-Rate-Limit-Policy"));
		return reply->rawHeader("X-Rate-Limit-Policy");
	};

	// Return the name(s) of the rule(s) from a network reply
	QByteArrayList GetRules(QNetworkReply* const reply) {
		assert(reply->hasRawHeader("X-Rate-Limit-Rules"));
		QByteArrayList names = reply->rawHeader("X-Rate-Limit-Rules").split(',');
		assert(names.size() > 0);
		return names;
	}

	// Return a list of one or more items that define a rule's limits.
	QByteArrayList GetLimits(QNetworkReply* const reply, const QByteArray& rule) {
		const QByteArray header = "X-Rate-Limit-" + rule;
		assert(reply->hasRawHeader(header));
		QByteArrayList things = reply->rawHeader(header).split(',');
		assert(things.size() > 0);
		return things;
	}

	// Return a list of one or more items that define a rule's current state.
	QByteArrayList GetStates(QNetworkReply* const reply, const QByteArray& rule) {
		const QByteArray header = "X-Rate-Limit-" + rule + "-State";
		assert(reply->hasRawHeader(header));
		QByteArrayList things = reply->rawHeader(header).split(',');
		assert(things.size() > 0);
		return things;
	}

	// Return the date from the HTTP reply header.
	QDateTime GetDate(QNetworkReply* const reply) {
		assert(reply->hasRawHeader("Date"));
		QString timestamp = QString(reply->rawHeader("Date"));
		if (timestamp.endsWith("GMT")) {
			// It was necessary to replace GMT with UTC for QDateTime::fromString() to
			// correctly parse the timestamp. There is probably a better way to handle this,
			// because the current implementation *might* break if the responses start
			// including timezone information in a slightly different format, like "GMT-0".
			timestamp.chop(3);
			timestamp.append("UTC");
		};
		const QDateTime date = QDateTime::fromString(timestamp, "ddd, dd MMM yyyy hh:mm:ss t");
		assert(date.isValid());
		return date;
	}

	// Return the "endpoint" for a given URL. Since this code assumes the only requests
	// we care about are those to pathofexile.com, the endpoint is effectively defined
	// by the url's path.
	//
	// For urls which are not rate limited, the string "<NO_ENDPOINT>" is returned.
	// This includes requests to the Path of Exile main page, which have a path of "/"
	// and do not have a rate limit policy... yet?
	QString GetEndpoint(const QUrl& url) {
		const QString& host = url.host();
		const QString& path = url.path();
		if (((host == "www.pathofexile.com") || (host == "pathofexile.com")) && (path != "/")) {
			return path;
		} else {
			return "<NO_ENDPOINT>";
		};
	}

	//------------------------------------------------------------------------------
	// Next, declarations for the classes that represent a rate-limit policy
	//------------------------------------------------------------------------------
	//
	// Each API response has a rate-limit policy that applies to it.
	// Those responses are present in the HTTP reply headers. Here's
	// how they are concieved, briefly:
	// 
	//  Every endpoint only has one applicable policy.
	//  Different endpoints may share the same rate limit policy.
	// 
	//  A policy has a name.
	//  A policy has one or more rules.
	//  A policy applies to one or more endpoints.
	// 
	//  Each rule has a name.
	//  Each rule has one or more limitation items.
	// 
	//  Each limitation item defines one set of limits
	//  Each limitation item comes with information on the state of that limitation.
	//
	// For any request against a rate-limited endpoint, only one policy applies, but
	// all of limitations for each item of every rule within that policy are checked.

	struct RateLimitElement {
		RateLimitElement(int hits_, int period_, int restriction_);
		int hits;
		int period;
		int restriction;
	};

	// Both RateLimitItem and RateLimitRule have default constructors because
	// they are the two policy-related classes where it's useful to preallocate
	// arrays of known size.
	// 
	// Specifically, this is used by RateLimit::Init(), by the RateLimitPolicy
	// constructor which parses a network reply.
	//
	// I avoided using default arguments because I find them confusing and 
	// more likely to result in unintended consequences.

	struct RateLimitItem {
		RateLimitItem();
		RateLimitItem(int hits, int period, int restriction);
		RateLimitElement limit;
		RateLimitElement state;
	};

	struct RateLimitRule {
		RateLimitRule();
		RateLimitRule(QString name_, std::vector<RateLimitItem> items_);
		QString name;
		std::vector<RateLimitItem> items;
	};

	struct RateLimitPolicy {
		RateLimitPolicy(QString name_, QStringList endpoints_);
		RateLimitPolicy(QNetworkReply* const reply);
		QString name;
		QDateTime timestamp;
		QStringList endpoints;
		std::vector<RateLimitRule> rules;
	};

	// The ACTIVE_WAITING state is used to update the status bar. The others aren't used yet.
	enum class RequestState {CREATED, QUEUED, ACTIVE, ACTIVE_WAITING, SENT, REPLIED, DISPATCHED, FINISHED};

	struct RateLimitedRequest {

		// Construct a new rate-limited request.
		RateLimitedRequest(const QNetworkRequest request, const Callback callback);

		// The state of the request.
		RequestState state;

		// Unique identified for each request, even through different requests can be
		// routed to different policy managers based on different endpoints.
		const unsigned long id;

		// A copy of this request's API endpoint, if any.
		const QString endpoint;

		// A copy of the network request that's going to be sent.
		const QNetworkRequest network_request;

		// A pointer where the reply can be found after this request is sent.
		QNetworkReply* network_reply;

		// The function to be called when a non-rate-limit reply is recieved.
		const Callback worker_callback;
		
		// The time a reply was made baesd on the reply's HTTP Date header.
		QDateTime reply_time;

		// The HTTP status of the reply.
		int reply_status;

	private:
		// Total number of requests that have every been constructed.
		static unsigned long request_count;
	};

	//------------------------------------------------------------------------------
	// Each rate-limit policy has it's own manager, defined here
	//------------------------------------------------------------------------------

	class RateLimitManager {
		//-------------------------------------------------------------------------
		// RateLimitManager - instance members and methods
		//-------------------------------------------------------------------------
	public:
		// Construct a rate limit manager with the specified policy. The constructor must be
		// public because it's called by std::make_unique().
		RateLimitManager(std::unique_ptr<RateLimitPolicy>);

	private:
		// Each rate limit manager has a unique id. This was mainly used in
		// initial debugging because I am new to unique_ptr and very inexperienced
		// with C++ concepts like memory management and reference copying.
		const unsigned long id;

		// Keeps track of how many requests this policy manager has sent.
		unsigned long requests_sent;

		// Returns true if this policy applies to the endpoint.
		bool IsApplicable(const QString& endpoint);

		// Move a request into to this manager's queue.
		void QueueRequest(std::unique_ptr<RateLimitedRequest> request);

		// This is called whenever the policy is update, which happens either
		// at construction inside Init() or when a QNetworkReply with a
		// X-Rate-Limit-Policy header is received.
		void OnPolicyUpdate();

		// If you guessed that this sends the currently active request. The
		// active request is stored as a member variable so that it doesn't have
		// to be passed around in lambda functors, which is tough to do with
		// unique pointers, beacuse they are fussy about being copied.
		void SendActiveRequest();

		// This is called when a reply has been received. Like the unique pointer
		// to the active request, the network reply is stored as a member.
		void ReceiveReply();

		// Resend the active request after the delay specified in the active reply.
		void ResendAfterViolation();

		// Keep a unique_ptr to the policy associated with this manager,
		// which will be updated whenever a reply with the X-Rate-Limit-Policy
		// header is received.
		std::unique_ptr<RateLimitPolicy> policy;

		// Simple flag to check if the active_request is in use. It's possible
		// to detect this by checking the status of the active request pointer,
		// but using a separate boolean flag is claer.
		bool busy;
		
		// Keep track of wether a violation was detected. Currently this is
		// only used to update the program status so the user knows wether
		// a reply is being delay to a violation or not.
		bool violation;

		// This timer sends the active request.
		QTimer active_request_timer;

		// Unique pointer to the currently active request.
		std::unique_ptr<RateLimitedRequest> active_request;

		// Other requests in this list have been queued up. When an active request
		// has been successfully send and replied, the next request will be taken
		// from this queue.
		std::list<std::unique_ptr<RateLimitedRequest>> request_queue;

		// When a reply is recieved and the policy state has been updated or a 
		// rate violation has been detected, the next possible send time is calculated
		// and stored here.
		QDateTime next_send;

		// We use a history of the received reply times so that we can calculate
		// when the next safe send time will be. This allows us to calculate the
		// least delay necessary to stay compliant.
		//
		// A circular buffer is used because it's fast to access, and the number
		// of items we have to store only changes when a rate limit policy
		// changes, which should not happen regularly, but we handle that case, too.
		boost::circular_buffer<QDateTime> known_reply_times;

		//-------------------------------------------------------------------------
		// RateLimitManager - static members and methods
		//-------------------------------------------------------------------------
	public:
		// Must be called before submitting any requests.
		static void Init(QNetworkAccessManager* network_manager, ItemsManagerWorker* items_worker);

		// Submits a request to the appropriate rate limit manager.
		static void Submit(QNetworkRequest network_request, Callback request_callback);

	private:
		// When a request has been successfully replied-to, then it's ready to be
		// dispatched. There's a special function for this because replies may come
		// back in a different order than they were submitted. This function
		// keeps track of which replies have been recieved and triggers callback 
		// in order, so the calling code doesn't have to worry about order.
		static void Dispatch(std::unique_ptr<RateLimitedRequest> request);

		// Used to send network requests.
		static QNetworkAccessManager* network_manager;

		// Used to update the program state during throttling.
		static ItemsManagerWorker* items_worker;

		// Flag to make sure Init() is only called once.
		static bool initialized;

		// Total number of policy managers that have been constructed.
		static unsigned long manager_count;

		// This timer updates the program status bar.
		static QTimer status_updater;

		// Update the program status while we wait to send the next request
		// so the user sees something happening.
		static void UpdateStatus();

		// One manager to handle requests that none of the existing policies
		// apply to, including non-API requests.
		static std::unique_ptr<RateLimitManager> default_manager;

		// One manager for each rate limit policy.
		static std::vector<std::unique_ptr<RateLimitManager>> managers;

		// Move finished requests into their own list so they can be reordered by
		// request id, which is how we guarantee that request callbacks will be
		// dispatched in order.
		static std::list<std::unique_ptr<RateLimitedRequest>> finished_requests;

		// Request id of the next request that should be sent back to the application
		static unsigned long next_request_to_send;
	};
}

RateLimitElement::RateLimitElement(int hits_, int period_, int restriction_) :
	hits(hits_),
	period(period_),
	restriction(restriction_) {};

RateLimitItem::RateLimitItem() :
	limit(0, 0, 0),
	state(0, 0, 0) {};

RateLimitItem::RateLimitItem(int hits, int period, int restriction) :
	limit(hits, period, restriction),
	state(0, 0, 0) {};

RateLimitRule::RateLimitRule() {};

RateLimitRule::RateLimitRule(QString name_, std::vector<RateLimitItem> items_) :
	name(name_),
	items(items_) {};

RateLimitPolicy::RateLimitPolicy(QString name_, QStringList endpoints_) :
	name(name_),
	endpoints(endpoints_),
	timestamp(QDateTime::currentDateTime()) {};

RateLimitPolicy::RateLimitPolicy(QNetworkReply* const reply) :
	name(GetPolicy(reply)),
	timestamp(GetDate(reply))
{

	const QByteArrayList rule_names = GetRules(reply);
	const int rule_count = rule_names.size();

	// Allocate a new vector of rules for this policy.
	rules = std::vector<RateLimitRule>(rule_count);

	// Iterate over all the rule names expected.
	for (int i = 0; i < rule_count; ++i) {

		// Get information from this rule.
		const QByteArray& rule_name = rule_names[i];
		const QByteArrayList limits = GetLimits(reply, rule_name);
		const QByteArrayList states = GetStates(reply, rule_name);
		const int item_count = limits.size();
		assert(item_count == states.size());

		// Set the rule name.
		RateLimitRule& rule = rules[i];
		rule.name = rule_name;

		// Allocate a new vector of items for this rule.
		rule.items = std::vector<RateLimitItem>(item_count);

		for (int j = 0; j < item_count; ++j) {

			const QByteArrayList limit_parts = limits[j].split(':');
			const QByteArrayList state_parts = states[j].split(':');
			assert(limit_parts.size() == 3);
			assert(state_parts.size() == 3);

			RateLimitItem& item = rule.items[j];

			item.limit.hits = limit_parts[0].toInt();
			item.limit.period = limit_parts[1].toInt();
			item.limit.restriction = limit_parts[2].toInt();

			item.state.hits = state_parts[0].toInt();
			item.state.period = state_parts[1].toInt();
			item.state.restriction = state_parts[2].toInt();

			assert(item.limit.period == item.state.period);
		};
	};
}

//------------------------------------------------------------------------------
// Local class that represents a single rate-limit request
//------------------------------------------------------------------------------

// Create a new rate-limited request.
RateLimitedRequest::RateLimitedRequest(const QNetworkRequest request, const RateLimit::Callback callback) :
	id(++request_count),
	state(RequestState::CREATED),
	endpoint(GetEndpoint(request.url())),
	network_request(request),
	network_reply(nullptr),
	reply_time(QDateTime()),
	reply_status(-1),
	worker_callback(callback)
{};

unsigned long RateLimitedRequest::request_count = 0;

//------------------------------------------------------------------------------
// Each rate-limit policy has it's own manager, defined here
//------------------------------------------------------------------------------

QNetworkAccessManager* RateLimitManager::network_manager = nullptr;
ItemsManagerWorker* RateLimitManager::items_worker = nullptr;
bool RateLimitManager::initialized = false;

// In the beginning, there were zero rate limit managers.
unsigned long RateLimitManager::manager_count = 0;

// Used to update the program status.
QTimer RateLimitManager::status_updater;

// Default manager for non-rate-limited requests.
std::unique_ptr<RateLimitManager> RateLimitManager::default_manager = nullptr;

// All the rate limit managers that have been created so far.
std::vector<std::unique_ptr<RateLimitManager>> RateLimitManager::managers = {};

// All the requests that have finished and are ready for callback.
std::list<std::unique_ptr<RateLimitedRequest>> RateLimitManager::finished_requests = {};

// Request id of the next request we expect to dispatch.
unsigned long RateLimitManager::next_request_to_send = 1;

// Initalized the rate limit manager.
void RateLimitManager::Init(QNetworkAccessManager* manager, ItemsManagerWorker* worker) {

	// Make sure we haven't been initialized before, e.g. by another thread
	// or a different copy of the application or something. I'm not sure if
	// this would ever happen, but it feels like a safe thing to check.
	assert(initialized == false);

	// Save the pointers we need to send requests and update program status.
	network_manager = manager;
	items_worker = worker;

	// Setup the program status update timer.
	status_updater.setSingleShot(false);
	status_updater.setInterval(1000);
	QObject::connect(&status_updater, &QTimer::timeout, [=]() { UpdateStatus(); });

	// Construct the default manager for requests without a rate-limited endpoint
	default_manager = std::make_unique<RateLimitManager>(
		std::make_unique<RateLimitPolicy>(
			QString("<NO_POLICY>"),
			QStringList({ "<NO_ENDPOINT>" })));

	// Read ratelimits.json
	//QDir jsondir(QCoreApplication::applicationDirPath());
	//QString jsonpath = jsondir.filePath("ratelimits.json");
	QFile jsonfile(":/ratelimits.json");
	if (!jsonfile.open(QIODevice::ReadOnly | QFile::Text)) {
		QLOG_ERROR() << "Could not open ratelimits.json:" << jsonfile.errorString();
		throw std::runtime_error("Could not open ratelimits.json");
	};
	QByteArray jsoncontents = jsonfile.readAll();
	jsonfile.close();

	// Parse ratelimits.json
	rapidjson::Document document;
	document.Parse(jsoncontents.data());
	if (document.HasParseError()) {
		QLOG_ERROR() << "Malformed ratelimits.json file:"
			<< rapidjson::GetParseError_En(document.GetParseError());
		throw std::runtime_error("Could not parse ratelimits.json");
	};
	assert(document.IsArray());

	// Build policy managers for each of the policies in the rate limits json document.
	for (rapidjson::SizeType i = 0; i < document.Size(); ++i) {

		const rapidjson::Value& item = document[i];
		assert(item.HasMember("policy-name"));
		assert(item.HasMember("policy-endpoints"));

		const rapidjson::Value& json_policy = item["policy-name"];
		const rapidjson::Value& json_endpoints = item["policy-endpoints"];
		assert(json_policy.IsString());
		assert(json_endpoints.IsArray());

		QString policy_name = json_policy.GetString();
		QStringList policy_endpoints = {};
		for (rapidjson::SizeType j = 0; j < json_endpoints.Size(); ++j) {
			const rapidjson::Value& json_endpoint = json_endpoints[i];
			assert(json_endpoint.IsString());
			QString endpoint = json_endpoints[j].GetString();
			policy_endpoints.push_back(endpoint);
		};
		std::unique_ptr<RateLimitPolicy> p = std::make_unique<RateLimitPolicy>(policy_name, policy_endpoints);
		std::unique_ptr<RateLimitManager> pm = std::make_unique<RateLimitManager>(std::move(p));
		managers.push_back(std::move(pm));
	};

	initialized = true;
}

void RateLimitManager::Submit(QNetworkRequest network_request, Callback request_callback)
{
	std::unique_ptr<RateLimitedRequest> request = std::make_unique<RateLimitedRequest>(network_request, request_callback);

	// Use the default manager the endpoint is unknown.
	if (request->endpoint == "<NO_ENDPOINT>") {
		default_manager->QueueRequest(std::move(request));
	} else {
		// Otherwise use the manager that knows this endpoint
		for (auto& manager : managers) {
			if (manager->IsApplicable(request->endpoint)) {
				manager->QueueRequest(std::move(request));
				return;
			};
		};
		// At this point, if none of the managers matched, then it's likely
		// that policies have changed and ratelimits.json needs updating.
		throw std::runtime_error("no policy matches the request endpoint: " + request->endpoint.toStdString());
	};
}

void RateLimitManager::Dispatch(std::unique_ptr<RateLimitedRequest> request)
{
	// First, insert this request into the queue of waiting
	// items so that the queue is always ordered based on
	// request id.
	if (finished_requests.empty()) {

		// The queue is empty.
		finished_requests.push_back(std::move(request));

	} else if (request->id > finished_requests.back()->id) {

		// The request belongs at the end.
		finished_requests.push_back(std::move(request));

	} else {

		// Find where in the queue this request fits.
		for (auto pos = finished_requests.begin(); pos != finished_requests.end(); ++pos) {

			// Order by request id.
			if (request->id < pos->get()->id) {
				finished_requests.insert(pos, std::move(request));
				break;
			};
		};
	};

	// Second, check to see if we can send one or more
	// requests back.
	while (finished_requests.empty() == false) {

		// Stop if the next request isn't the one we are waiting for.
		if (next_request_to_send != finished_requests.front()->id) {
			break;
		};

		// Take this request off the front of the queue.
		std::unique_ptr<RateLimitedRequest> request = std::move(finished_requests.front());
		finished_requests.pop_front();
		++next_request_to_send;

		// Trigger the callback for this request now.
		request->worker_callback(request->network_reply);
		request->network_reply->deleteLater();
		request = nullptr;
	};
}

// Create a new rate limit manager based on an existing policy.
RateLimitManager::RateLimitManager(std::unique_ptr<RateLimitPolicy> policy_) :
	id(++manager_count),
	requests_sent(0),
	policy(std::move(policy_)),
	busy(false),
	violation(false),
	next_send(QDateTime::currentDateTime())
{
	active_request_timer.setSingleShot(true);
	QObject::connect(&active_request_timer, &QTimer::timeout, [=]() { SendActiveRequest(); });
}

// Update this policy manager when the policy has changed. This means updating
// the number of reply times we keep around of the policy's limits have changed,
// and figuring out the next time a request can be sent without violating this
// policy.
void RateLimitManager::OnPolicyUpdate() {

	// Need to know the current number of items in the reply
	// history so we don't try to read pas them.
	const int current_history_size = known_reply_times.size();

	// Determine how many hits we need to keep track of to keep track
	// of this policy.
	int new_history_capacity = 0;

	for (const auto& rule : policy->rules) {

		for (const auto& item : rule.items) {

			const int& current_hits = item.state.hits;
			const int& maximum_hits = item.limit.hits;
			const int& period_tested = item.limit.period;

			// Average time (in seconds) that requests can be submitted
			// and meet the limitation imposed by this item.
			const float t = float(item.limit.period) / float(item.limit.hits);

			// First, update the maximum history capacity if needed.
			if (maximum_hits > new_history_capacity) {
				new_history_capacity = maximum_hits;
			};

			// Second, check to see if we are at (or past) the current
			// rate limit policy's maximum. If that's the case, we need
			// to update the next time it will be safe to send a request.
			//
			// For example, if a limitation allows up to 10 requests in a
			// 60 second period, then if there have already been 10 hits
			// against that limitation, we cannot make another until the
			// first of those 10 hits falls out of the 60 second period.
			//
			// This is why we store a history of reply times.
			//
			// However, it's possible we hit a rate limit policy on the
			// very first request the application makes. This can happen
			// if the application was just restarted after a prior rate
			// limit violation.
			//
			// Therefore, there have been 10 hits in the last 60 seconds
			// against the example policy, but the application only knows
			// about 4 of them, then the best we can do is go back to
			// the earliest of those 4 replies and add the restriction
			// to that request's timestamp.
			//
			// This means the only time a real rate limit violation
			// should occur is if the application's very first request
			// is restricted.
			if (current_hits >= maximum_hits) {

				// Determine how far back into the history we can look.
				int n = current_hits;
				if (n > current_history_size) {
					n = current_history_size;
				};

				// Start with the timestamp of the earliest known
				// reply relevant to this limitation.
				QDateTime starting_time;
				if (n < 1) {
					starting_time = QDateTime::currentDateTime();
				} else {
					starting_time = known_reply_times[n - 1];
				};

				// Calculate the next time it will be safe to send a request.
				const QDateTime next_safe_time = starting_time.addSecs(period_tested);
				assert(next_safe_time.isValid());

				// Update this manager's send time only if it's later
				// than the manager thinks we need to wait.
				if (next_safe_time > next_send) {
					next_send = next_safe_time;
				};
			};
		};
	};
	
	// Grow the history capacity if needed.
	if (known_reply_times.capacity() < new_history_capacity) {
		QLOG_WARN() << policy->name
			<< "increasing history capacity"
			<< "from" << known_reply_times.capacity()
			<< "to" << new_history_capacity;
		known_reply_times.set_capacity(new_history_capacity);
	};
}

// Return true if this manager's policy applies to the endpoint.
bool RateLimitManager::IsApplicable(const QString& endpoint) {
	return policy->endpoints.contains(endpoint);
}

// If the rate limit manager is busy, the request will be queued.
// Otherwise, the request will be sent immediately, making the
// manager busy and causing subsequent requests to be queued.
void RateLimitManager::QueueRequest(std::unique_ptr<RateLimitedRequest> request) {
	if (busy) {
		request->state = RequestState::QUEUED;
		QLOG_TRACE() << policy->name << "queuing request" << request->id;
		request_queue.push_back(std::move(request));
	} else {
		busy = true;
		active_request = std::move(request);
		active_request->state = RequestState::ACTIVE;
		SendActiveRequest();
	};
}

// Send the active request at the next time it will be safe to do so
// without violating the rate limit policy.
void RateLimitManager::SendActiveRequest() {

	assert(next_send.isValid());
	int msec_delay = QDateTime::currentDateTime().msecsTo(next_send);
	int request_id = active_request->id;
	if (msec_delay > 0) {
		// Need to wait and rerun this function when it's safe to send.
		QLOG_TRACE() << policy->name
			<< "waiting" << (msec_delay / 1000)
			<< "seconds to send active request" << active_request->id
			<< "at" << next_send.toLocalTime().toString();

		// Update the request and start updating the program status with the timer.
		active_request->state = RequestState::ACTIVE_WAITING;
		active_request_timer.setInterval(msec_delay);
		active_request_timer.start();

		// Make sure the program status is being updated.
		if (status_updater.isActive() == false) {
			// The timer is running in another thread, so we have to use invokeMethod.
			QMetaObject::invokeMethod(&status_updater, "start", Qt::QueuedConnection);
		};

	} else {
		// Send immediately.
		QLOG_TRACE() << policy->name
			<< "sending active request" << active_request->id
			<< "to" << active_request->endpoint
			<< "via" << active_request->network_request.url().toString();
		assert(active_request->network_reply == nullptr);
		QNetworkReply* reply = network_manager->get(active_request->network_request);
		active_request->state = RequestState::SENT;
		active_request->network_reply = reply;
		QObject::connect(reply, &QNetworkReply::finished, [=]() { ReceiveReply(); });
	};
}

// Called when the active request's network_reply is finished.
void RateLimitManager::ReceiveReply() {

	QNetworkReply* reply = active_request->network_reply;
	active_request->state = RequestState::REPLIED;
	active_request->reply_time = GetDate(reply);
	active_request->reply_status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

	QLOG_TRACE() << policy->name
		<< "received reply for request" << active_request->id
		<< "with status code" << active_request->reply_status;

	if (reply->hasRawHeader("X-Rate-Limit-Policy")) {

		// Get the rate limit policy name from the header.
		const QString reply_policy = reply->rawHeader("X-Rate-Limit-Policy");
		assert(reply_policy == policy->name);

		// This reply came with a policy update, so save the reply time.
		known_reply_times.push_front(active_request->reply_time);

		// Update the new policy with all of the endpoints already
		// associated with the existing policy, because that *should*
		// never change.
		QStringList current_endpoints = policy->endpoints;
		if (current_endpoints.contains(active_request->endpoint) == false) {
			current_endpoints.push_back(active_request->endpoint);
		};
		policy = std::make_unique<RateLimitPolicy>(reply);
		policy->endpoints = current_endpoints;

		// Now examine the new policy and update ourselves accordingly.
		OnPolicyUpdate();
	};

	// Check for errors before dispatching the request
	if (active_request->reply_status == RATE_LIMIT_VIOLATION_STATUS) {

		// There was a rate limit violation.
		ResendAfterViolation();

	} else if (active_request->network_reply->error() != QNetworkReply::NoError) {

		// Some other HTTP error was encountered.
		QLOG_ERROR() << policy->name
			<< "request" << active_request->id
			<< "reply status was " << active_request->reply_status
			<< "and error was" << reply->error();
		throw std::runtime_error("unhandled http error");

	} else {

		// No errors or violations, so move this request to the dispatch queue.
		violation = false;
		Dispatch(std::move(active_request));
		if (request_queue.empty()) {
			busy = false;
		} else {
			// Stay busy and activate the next request in the queue.
			active_request = std::move(request_queue.front());
			request_queue.pop_front();
			SendActiveRequest();
		};
	};
}

// A violation was detected, so we need to wait to resend the active request.
void RateLimitManager::ResendAfterViolation()
{
	// Set the violation flag now. It will be unset when a reply is received that doesn't
	// indicat a violation.
	violation = true;

	// Determine how long we need to wait.
	const int delay_sec = active_request->network_reply->rawHeader("Retry-After").toInt();
	const int delay_msec = (delay_sec * 1000) + EXTRA_RATE_VIOLATION_MSEC;
	QLOG_ERROR() << policy->name
		<< "RATE LIMIT VIOLATION on request" << active_request->id << "of" << delay_sec << "seconds";

	// Update the time it will be safe to send again.
	next_send = active_request->reply_time.addMSecs(delay_msec);
	assert(next_send.isValid());

	// Reset this request before resending it, which means
	// letting QT know the assocated reply can be deleted.
	active_request->network_reply->deleteLater();
	active_request->network_reply = nullptr;
	active_request->reply_time = QDateTime();
	active_request->reply_status = -1;
	SendActiveRequest();
}

// Update the program status based on how long we will have to wait for the next send.
void RateLimitManager::UpdateStatus()
{
	// Loop over all the managers and see which ones have an active request
	// that is waiting to be sent. Of these, keep the details of the one
	// that is the closes to being sent.
	//
	// Since mulitiple requests can be active and waiting at once, we just
	// want to show how much time is left until whichever is going to be
	// sent soonest.
	bool found_one = false;
	QDateTime time = QDateTime();
	QString policy_name = QString();
	bool violation = false;

	for (auto& manager : managers) {
		// Only check managers that have a valid active request.
		// Only check managers where the active request is waiting to be sent.
		if ((manager->active_request != nullptr) &&
			(manager->active_request->state == RequestState::ACTIVE_WAITING)) {
			// Save some details from this active request if it's the first
			// waiting request we've encountered, or if it's going to be
			// sent sooner that the last one we found.
			if ((found_one == false) || (manager->next_send <= time)) {
				time = manager->next_send;
				policy_name = manager->policy->name;
				violation = manager->violation;
				found_one = true;
			};
		};
	};

	// Either update the status bar if we found an actively waiting request,
	// or stop the time.
	if (found_one) {
		// Update the program status bar.
		CurrentStatusUpdate status;
		if (violation) {
			status.state = ProgramState::RateLimitViolation;
			status.message = "RATE LIMIT VIOLATION: retrying in %1 seconds at %2 due to %3";
		} else {
			status.state = ProgramState::RateLimitPause;
			status.message = "RATE LIMIT THROTTLE: waiting %1 seconds until %2 due to %3";
		};
		status.message = status.message
			.arg(QDateTime::currentDateTime().secsTo(time))
			.arg(time.toLocalTime().toString())
			.arg(policy_name);
		emit items_worker->StatusUpdate(status);
	} else {
		// No active requests appear to be waiting. Because the timer is running
		// in another thread, we use invokeMethod here.
		QMetaObject::invokeMethod(&status_updater, "stop", Qt::QueuedConnection);
	}
}

//=========================================================================================
// CONNECT PUBLIC FUNCTIONS TO INTERNAL IMPLEMENTATION
//=========================================================================================

// Construct a new rate limiter
void RateLimit::Init(QNetworkAccessManager* manager, ItemsManagerWorker* worker)
{
	RateLimitManager::Init(manager, worker);
}

// Submit a new request.
void RateLimit::Submit(QNetworkRequest network_request, Callback request_callback)
{
	RateLimitManager::Submit(network_request, request_callback);
}
