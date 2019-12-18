const ERRORS = {
  401: {
    err: "Unauthorized",
    detail:
      "Request had Authorization header but token was missing or invalid. Please ensure your API token is valid."
  },
  403: {
    err: "Access Denied",
    detail: "Not enough access permissions."
  },
  404: {
    err: "Not Found",
    detail: "Requested item doesn’t exist or not enough access permissions."
  },
  429: {
    err: "Too Many Requests",
    detail:
      "Daily number of requests exceeds limit. Check Retry-After header to get information about request delay."
  },
  500: {
    err: "Server Error",
    detail: "Something went wrong on our End (Intel471 API)"
  }
};

const handleRequestStatusCode = (entity, statusCode, body) => {
  let result;
  let error;
  if (statusCode === 200) {
    result = {
      entity,
      body
    };
  } else if (statusCode === 404 || statusCode === 202) {
    result = {
      entity,
      body: null
    };
  } else {
    error = 
      ERRORS[statusCode] || 
      ERRORS[Math.round(statusCode / 10) * 10] ||
      {
        err: body,
        detail: `${body.error}: ${body.message}`
      };
  }
  return [error, result];
};

module.exports = handleRequestStatusCode;
