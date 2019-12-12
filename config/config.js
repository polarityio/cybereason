module.exports = {
  name: "CyberReason",
  acronym: "CR",
  description:"CyberReason",
  entityTypes: ['IPv4', 'domain', "SHA1", "MD5"],
  styles: ["./styles/sc.less"],
  block: {
    component: {
      file: "./components/sc-block.js"
    },
    template: {
      file: "./templates/sc-block.hbs"
    }
  },
  summary: {
    component: {
      file: "./components/sc-summary.js"
    },
    template: {
      file: "./templates/sc-summary.hbs"
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    cert: "",
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    key: "",
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    passphrase: "",
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    ca: "",
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: "",

    rejectUnauthorized: false
  },
  logging: {
    level: "trace" //trace, debug, info, warn, error, fatal
  },
  options: [
    {
      key: "url",
      name: "Base CyberReason API URL",
      description:
        "The base URL for the CyberReason API including the schema (i.e., https://)",
      type: "text",
      default: "",
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: "username",
      name: "Valid Username",
      description: "Valid CyberReason Username",
      default: "",
      type: "text",
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: "password",
      name: "Valid Password",
      description: "Valid CyberReason Password",
      default: "",
      type: "password",
      userCanEdit: true,
      adminOnly: false
    }
  ]
};
