const config = require("../config/config");
const fs = require("fs");
const request = require("postman-request");

const getRequestWithDefaults = () => {
  let defaults = {};

  const { cert, key, ca, passphrase, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === "string" && cert.length > 0) 
    defaults.cert = fs.readFileSync(cert);

  if (typeof key === "string" && key.length > 0) 
    defaults.key = fs.readFileSync(key);

  if (typeof ca === "string" && ca.length > 0) 
    defaults.ca = fs.readFileSync(ca);

  if (typeof passphrase === "string" && passphrase.length > 0) 
    defaults.passphrase = passphrase;

  if (typeof proxy === "string" && proxy.length > 0) 
    defaults.proxy = proxy;

  if (typeof rejectUnauthorized === "boolean") 
    defaults.rejectUnauthorized = rejectUnauthorized;

  return request.defaults(defaults);
};

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== "string" ||
    (typeof options[optionName].value === "string" && 
    options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(errors, options, "url", "You must provide a valid API URL");
  validateStringOption(errors, options, "username", "You must provide a valid Username");
  validateStringOption(errors, options, "password", "You must provide a valid Password");
  callback(null, errors);
}

module.exports = {
  validateOptions,
  getRequestWithDefaults
};
