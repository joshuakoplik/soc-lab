/** @type {import('next').NextConfig} */
const nextConfig = {
  // Small, self-contained runtime image -- no dev toolchain shipped.
  output: 'standalone',
};

module.exports = nextConfig;
