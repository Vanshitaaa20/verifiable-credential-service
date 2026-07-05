// Every route error responds with the same shape: { error, details }.
// Status code is carried on the error itself so route handlers just throw
// and one error-handling middleware (see server.ts) does the formatting.
export class ApiError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public details: unknown = null,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// 400: the request itself is malformed (missing/wrong-typed fields, bad
// param format) — rejected before any business logic runs.
export class ValidationError extends ApiError {
  constructor(message: string, details: unknown = null) {
    super(message, 400, details);
    this.name = 'ValidationError';
  }
}

// 404: the request is well-formed but references something that doesn't exist.
export class NotFoundError extends ApiError {
  constructor(message: string, details: unknown = null) {
    super(message, 404, details);
    this.name = 'NotFoundError';
  }
}

// 422: the request is well-formed and references real resources, but the
// operation can't be carried out (e.g. revoking a credential that was never
// issued with a status list entry).
export class UnprocessableError extends ApiError {
  constructor(message: string, details: unknown = null) {
    super(message, 422, details);
    this.name = 'UnprocessableError';
  }
}
