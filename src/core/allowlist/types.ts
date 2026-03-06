export type AllowListEntry = {
  id: string;
  package: string;
  reason: string;
  expires: string; // ISO date string (YYYY-MM-DD)
};

export type AllowList = {
  ignore: AllowListEntry[];
};
