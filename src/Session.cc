// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Session.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/Val.h"
#include "zeek/Event.h"
#include "zeek/Desc.h"
#include "zeek/SessionManager.h"
#include "zeek/IP.h"

namespace zeek {

namespace detail {

void SessionTimer::Init(Session* arg_conn, timer_func arg_timer,
                        bool arg_do_expire)
	{
	conn = arg_conn;
	timer = arg_timer;
	do_expire = arg_do_expire;
	Ref(conn);
	}

SessionTimer::~SessionTimer()
	{
	if ( conn->RefCnt() < 1 )
		reporter->InternalError("reference count inconsistency in ~SessionTimer");

	conn->RemoveTimer(this);
	Unref(conn);
	}

void SessionTimer::Dispatch(double t, bool is_expire)
	{
	if ( is_expire && ! do_expire )
		return;

	// Remove ourselves from the connection's set of timers so
	// it doesn't try to cancel us.
	conn->RemoveTimer(this);

	(conn->*timer)(t);

	if ( conn->RefCnt() < 1 )
		reporter->InternalError("reference count inconsistency in SessionTimer::Dispatch");
	}

SessionKey::SessionKey(const void* session, size_t size, bool copy) : size(size)
	{
	data = reinterpret_cast<const uint8_t*>(session);
	if ( copy )
		CopyData();
	}

SessionKey::SessionKey(SessionKey&& rhs)
	{
	data = rhs.data;
	size = rhs.size;
	copied = rhs.copied;

	rhs.data = nullptr;
	rhs.size = 0;
	rhs.copied = false;
	}

SessionKey& SessionKey::operator=(SessionKey&& rhs)
	{
	if ( this != &rhs )
		{
		data = rhs.data;
		size = rhs.size;
		copied = rhs.copied;

		rhs.data = nullptr;
		rhs.size = 0;
		rhs.copied = false;
		}

	return *this;
	}

SessionKey::~SessionKey()
	{
	if ( copied )
		delete [] data;
	}

void SessionKey::CopyData()
	{
	if ( copied )
		return;

	copied = true;

	uint8_t *temp = new uint8_t[size];
	memcpy(temp, data, size);
	data = temp;
	}

bool SessionKey::operator<(const SessionKey& rhs) const
	{
	if ( size != rhs.size )
		return size < rhs.size;

	return memcmp(data, rhs.data, size) < 0;
	}

} // namespace detail

Session::Session(double t,
                 EventHandlerPtr timeout_event,
                 EventHandlerPtr status_update_event,
                 double status_update_interval)
	: start_time(t), last_time(t),
	  session_timeout_event(timeout_event),
	  session_status_update_event(status_update_event),
	  session_status_update_interval(status_update_interval)
	{
	record_contents = record_packets = 1;
	record_current_packet = record_current_content = 0;
	is_active = 1;
	timers_canceled = 0;
	inactivity_timeout = 0;
	installed_status_timer = 0;
	}

unsigned int Session::MemoryAllocation() const
	{
	return 0;
	}

void Session::Event(EventHandlerPtr f, analyzer::Analyzer* analyzer, const char* name)
	{
	if ( ! f )
		return;

	if ( name )
		EnqueueEvent(f, analyzer, make_intrusive<StringVal>(name), ConnVal());
	else
		EnqueueEvent(f, analyzer, ConnVal());
	}

void Session::EnqueueEvent(EventHandlerPtr f, analyzer::Analyzer* a, Args args)
	{
	// "this" is passed as a cookie for the event
	event_mgr.Enqueue(f, std::move(args), util::detail::SOURCE_LOCAL, a ? a->GetID() : 0, this);
	}

void Session::Describe(ODesc* d) const
	{
	d->Add(start_time);
	d->Add("(");
	d->Add(last_time);
	d->AddSP(")");
	}

void Session::SetLifetime(double lifetime)
	{
	ADD_TIMER(&Session::DeleteTimer, run_state::network_time + lifetime, 0,
	          detail::TIMER_CONN_DELETE);
	}

void Session::SetInactivityTimeout(double timeout)
	{
	if ( timeout == inactivity_timeout )
		return;

	// First cancel and remove any existing inactivity timer.
	for ( const auto& timer : timers )
		if ( timer->Type() == detail::TIMER_CONN_INACTIVITY )
			{
			detail::timer_mgr->Cancel(timer);
			break;
			}

	if ( timeout )
		ADD_TIMER(&Session::InactivityTimer,
		          last_time + timeout, 0, detail::TIMER_CONN_INACTIVITY);

	inactivity_timeout = timeout;
	}

void Session::EnableStatusUpdateTimer()
	{
	if ( installed_status_timer )
		return;

	if ( session_status_update_event && session_status_update_interval )
		{
		ADD_TIMER(&Session::StatusUpdateTimer,
		          run_state::network_time + session_status_update_interval, 0,
		          detail::TIMER_CONN_STATUS_UPDATE);
		installed_status_timer = 1;
		}
	}

void Session::CancelTimers()
	{
	// We are going to cancel our timers which, in turn, may cause them to
	// call RemoveTimer(), which would then modify the list we're just
	// traversing. Thus, we first make a copy of the list which we then
	// iterate through.
	TimerPList tmp(timers.length());
	std::copy(timers.begin(), timers.end(), std::back_inserter(tmp));

	for ( const auto& timer : tmp )
		detail::timer_mgr->Cancel(timer);

	timers_canceled = 1;
	timers.clear();
	}

void Session::DeleteTimer(double /* t */)
	{
	if ( is_active )
		Event(session_timeout_event, nullptr);

	session_mgr->Remove(this);
	}

void Session::AddTimer(timer_func timer, double t, bool do_expire,
                       detail::TimerType type)
	{
	if ( timers_canceled )
		return;

	// If the key is cleared, the session isn't stored in the session table
	// anymore and will soon be deleted. We're not installed new timers
	// anymore then.
	if ( ! IsKeyValid() )
		return;

	detail::Timer* conn_timer = new detail::SessionTimer(this, timer, t, do_expire, type);
	detail::timer_mgr->Add(conn_timer);
	timers.push_back(conn_timer);
	}

void Session::RemoveTimer(detail::Timer* t)
	{
	timers.remove(t);
	}

void Session::InactivityTimer(double t)
	{
	if ( last_time + inactivity_timeout <= t )
		{
		Event(session_timeout_event, nullptr);
		session_mgr->Remove(this);
		++detail::killed_by_inactivity;
		}
	else
		ADD_TIMER(&Session::InactivityTimer,
		          last_time + inactivity_timeout, 0,
		          detail::TIMER_CONN_INACTIVITY);
	}

void Session::StatusUpdateTimer(double t)
	{
	EnqueueEvent(session_status_update_event, nullptr, ConnVal());
	ADD_TIMER(&Session::StatusUpdateTimer,
	          run_state::network_time + session_status_update_interval, 0,
	          detail::TIMER_CONN_STATUS_UPDATE);
	}

void Session::RemoveConnectionTimer(double t)
	{
	RemovalEvent();
	session_mgr->Remove(this);
	}

} // namespace zeek
