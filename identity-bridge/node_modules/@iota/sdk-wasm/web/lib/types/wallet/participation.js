// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/**
 * All possible event status.
 */
export var EventStatus;
(function (EventStatus) {
    EventStatus["Upcoming"] = "upcoming";
    EventStatus["Commencing"] = "commencing";
    EventStatus["Holding"] = "holding";
    EventStatus["Ended"] = "ended";
})(EventStatus || (EventStatus = {}));
/**
 * The types of participation events.
 */
export var ParticipationEventType;
(function (ParticipationEventType) {
    /** A voting event. */
    ParticipationEventType[ParticipationEventType["Voting"] = 0] = "Voting";
    /** A staking event. */
    ParticipationEventType[ParticipationEventType["Staking"] = 1] = "Staking";
})(ParticipationEventType || (ParticipationEventType = {}));
//# sourceMappingURL=participation.js.map