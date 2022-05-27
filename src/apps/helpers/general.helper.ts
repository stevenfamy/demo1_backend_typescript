import { DateTime } from "luxon";

export const convertTimestamp = async (timestamp: number) =>
  DateTime.fromSeconds(timestamp, { zone: "Asia/Singapore" }).toISO();

export const convertToTimestamp = async (dateTime: string) =>
  DateTime.fromISO(dateTime, { zone: "Asia/Singapore" }).toSeconds();
