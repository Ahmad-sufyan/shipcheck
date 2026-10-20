/** @type {import('next').NextConfig} */
// shipcheck-expect: HTTP-006, HTTP-001, HTTP-002
const nextConfig = {
  reactStrictMode: true,
  images: {
    // shipcheck-expect: INFRA-004
    remotePatterns: [{ protocol: 'https', hostname: '**' }],
    // shipcheck-expect: INFRA-004
    dangerouslyAllowSVG: true,
  },
  experimental: {
    serverActions: {
      // shipcheck-expect: INFRA-004
      allowedOrigins: ['*'],
    },
  },
  // shipcheck-expect: SECRET-006
  productionBrowserSourceMaps: true,
}

export default nextConfig
