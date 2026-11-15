/** @type {import('next').NextConfig} */
const nextConfig = {
  // pg is a Node-only dependency used by the database layer; keep it out
  // of the client bundle and let the server use the real module.
  serverExternalPackages: ["pg"],
};
export default nextConfig;
