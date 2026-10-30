package com.secureconnect.app.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AutomaticRoutePolicyTest {
    @Test fun neverInterruptsLiveVpnOrKillSwitch() {
        assertEquals(AutomaticRoutePolicy.Action.KEEP_SESSION,
            AutomaticRoutePolicy.decide(VpnState.Connected, false, false))
        assertEquals(AutomaticRoutePolicy.Action.STOP_REQUIRED,
            AutomaticRoutePolicy.decide(VpnState.Blocked, false, false))
        assertEquals(AutomaticRoutePolicy.Action.STOP_REQUIRED,
            AutomaticRoutePolicy.decide(VpnState.Stopping, false, false))
    }

    @Test fun neverCreatesDuplicateConnectionAttempt() {
        assertEquals(AutomaticRoutePolicy.Action.WAIT,
            AutomaticRoutePolicy.decide(VpnState.Connecting, false, false))
        assertEquals(AutomaticRoutePolicy.Action.WAIT,
            AutomaticRoutePolicy.decide(VpnState.Validating, false, false))
        assertEquals(AutomaticRoutePolicy.Action.WAIT,
            AutomaticRoutePolicy.decide(VpnState.Idle, true, false))
        assertEquals(AutomaticRoutePolicy.Action.WAIT,
            AutomaticRoutePolicy.decide(VpnState.Idle, false, true))
    }

    @Test fun idleAndErrorMayReuseExistingXrayAutoSelection() {
        assertEquals(AutomaticRoutePolicy.Action.START_XRAY,
            AutomaticRoutePolicy.decide(VpnState.Idle, false, false))
        assertEquals(AutomaticRoutePolicy.Action.START_XRAY,
            AutomaticRoutePolicy.decide(VpnState.Error("offline"), false, false))
        assertTrue(AutomaticRoutePolicy.message(
            AutomaticRoutePolicy.Action.START_XRAY, false).contains("Xray"))
    }

    @Test fun connectedMessagePreservesCurrentSession() {
        assertTrue(AutomaticRoutePolicy.message(
            AutomaticRoutePolicy.Action.KEEP_SESSION, true).contains("Не переключаю"))
    }
}
