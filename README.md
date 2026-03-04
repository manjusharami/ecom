// app/api/users/route.test.ts
import { NextRequest } from "next/server";
import { GET, POST } from "./route";
import { validateToken } from "@/lib/jwtValidator";

// ── Mock jwtValidator ──────────────────────────────────────────────────────
jest.mock("@/lib/jwtValidator");

const mockValidateToken = validateToken as jest.Mock;

// ── Single Mock User ───────────────────────────────────────────────────────
const MOCK_USER = {
  oid: "user-123",
  name: "John Doe",
  email: "john@example.com",
  roles: ["Admin"],
};

// ── Helper ─────────────────────────────────────────────────────────────────
function makeRequest(
  method: "GET" | "POST",
  {
    token,
    body,
    searchParams,
  }: {
    token?: string;
    body?: Record<string, unknown>;
    searchParams?: Record<string, string>;
  } = {}
): NextRequest {
  const url = new URL("http://localhost/api/users");

  if (searchParams) {
    Object.entries(searchParams).forEach(([k, v]) =>
      url.searchParams.set(k, v)
    );
  }

  return new NextRequest(url.toString(), {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}

// ── GET Tests ──────────────────────────────────────────────────────────────
describe("GET /api/users", () => {
  beforeEach(() => jest.clearAllMocks());

  it("returns 401 when no Authorization header", async () => {
    const request = makeRequest("GET");
    const response = await GET(request);
    const json = await response.json();

    expect(response.status).toBe(401);
    expect(json.success).toBe(false);
  });

  it("returns 401 when token is expired", async () => {
    const err = new Error("jwt expired");
    err.name = "TokenExpiredError";
    mockValidateToken.mockRejectedValue(err);

    const request = makeRequest("GET", { token: "expired.token" });
    const response = await GET(request);
    const json = await response.json();

    expect(response.status).toBe(401);
    expect(json.message).toBe("jwt expired");
  });

  it("returns 403 when user has no valid role", async () => {
    mockValidateToken.mockResolvedValue({ ...MOCK_USER, roles: ["Unknown"] });

    const request = makeRequest("GET", { token: "valid.token" });
    const response = await GET(request);
    const json = await response.json();

    expect(response.status).toBe(403);
    expect(json.message).toBe("Forbidden");
  });

  it("returns 200 with data and correct id", async () => {
    mockValidateToken.mockResolvedValue(MOCK_USER);

    const request = makeRequest("GET", {
      token: "valid.token",
      searchParams: { id: "42" },
    });
    const response = await GET(request);
    const json = await response.json();

    expect(response.status).toBe(200);
    expect(json.success).toBe(true);
    expect(json.data.id).toBe("42");
    expect(json.data.requestedBy).toBe(MOCK_USER.email);
  });

  it("returns 500 on unexpected error", async () => {
    mockValidateToken.mockRejectedValue(new Error("DB connection failed"));

    const request = makeRequest("GET", { token: "valid.token" });
    const response = await GET(request);
    const json = await response.json();

    expect(response.status).toBe(500);
    expect(json.message).toBe("DB connection failed");
  });
});

// ── POST Tests ─────────────────────────────────────────────────────────────
describe("POST /api/users", () => {
  beforeEach(() => jest.clearAllMocks());

  it("returns 401 when no Authorization header", async () => {
    const request = makeRequest("POST");
    const response = await POST(request);
    const json = await response.json();

    expect(response.status).toBe(401);
    expect(json.success).toBe(false);
  });

  it("returns 403 when user is not Admin", async () => {
    mockValidateToken.mockResolvedValue({ ...MOCK_USER, roles: ["Reader"] });

    const request = makeRequest("POST", {
      token: "valid.token",
      body: { name: "Alice", email: "alice@example.com" },
    });
    const response = await POST(request);
    const json = await response.json();

    expect(response.status).toBe(403);
    expect(json.message).toBe("Forbidden: Admins only");
  });

  it("returns 400 when name is missing", async () => {
    mockValidateToken.mockResolvedValue(MOCK_USER);

    const request = makeRequest("POST", {
      token: "valid.token",
      body: { email: "alice@example.com" },
    });
    const response = await POST(request);
    const json = await response.json();

    expect(response.status).toBe(400);
    expect(json.message).toBe("name and email are required");
  });

  it("returns 400 when email is missing", async () => {
    mockValidateToken.mockResolvedValue(MOCK_USER);

    const request = makeRequest("POST", {
      token: "valid.token",
      body: { name: "Alice" },
    });
    const response = await POST(request);
    const json = await response.json();

    expect(response.status).toBe(400);
    expect(json.message).toBe("name and email are required");
  });

  it("returns 201 with created user", async () => {
    mockValidateToken.mockResolvedValue(MOCK_USER);

    const request = makeRequest("POST", {
      token: "valid.token",
      body: { name: "Alice", email: "alice@example.com" },
    });
    const response = await POST(request);
    const json = await response.json();

    expect(response.status).toBe(201);
    expect(json.success).toBe(true);
    expect(json.data.name).toBe("Alice");
    expect(json.data.email).toBe("alice@example.com");
    expect(json.data.createdBy).toBe(MOCK_USER.email);
    expect(json.data.id).toBeDefined();
  });

  it("returns 500 on unexpected error", async () => {
    mockValidateToken.mockRejectedValue(new Error("Unexpected failure"));

    const request = makeRequest("POST", { token: "valid.token" });
    const response = await POST(request);
    const json = await response.json();

    expect(response.status).toBe(500);
    expect(json.message).toBe("Unexpected failure");
  });
});
