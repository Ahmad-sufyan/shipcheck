/** @type {import('next').NextConfig} */
// shipcheck-expect: HTTP-006
const nextConfig = {
  reactStrictMode: true,
  images: {
    remotePatterns: [{ protocol: 'https', hostname: '*.supabase.co' }],
  },
  // shipcheck-expect: SECRET-006
  productionBrowserSourceMaps: true,
}

export default nextConfig
