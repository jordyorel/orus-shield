import { describe, expect, it } from "vitest";
import { match } from "./router";

describe("match", () => {
  it("matches parameters", () => {
    expect(match("/orgs/:org", "/orgs/abc")).toEqual({ org: "abc" });
    expect(match("/orgs/:org/:section", "/orgs/abc/actifs/")).toEqual({ org: "abc", section: "actifs" });
    expect(match("/", "/")).toEqual({});
  });

  it("rejects other shapes", () => {
    expect(match("/orgs/:org", "/orgs")).toBeNull();
    expect(match("/orgs/:org", "/orgs/a/b")).toBeNull();
    expect(match("/orgs/:org", "/orgs/%E0%A4%A")).toBeNull(); // malformed escape
  });
});
