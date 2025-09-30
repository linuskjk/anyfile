# Production Docker image for AnySend
# Use a small official Node base
FROM node:20-alpine

# Create app directory
WORKDIR /app

# Copy package manifests first (better layer caching)
COPY package*.json ./

# Install production dependencies only (no dev dependencies present yet)
RUN npm install --omit=dev && npm cache clean --force

# Copy source
COPY . .

# Ensure uploads directory exists (will also be a volume)
RUN mkdir -p uploads

# Expose port
EXPOSE 3000

# Environment variable documentation (override at runtime):
#   PORT=3000
#   ALLOWED_ORIGINS=https://linusk.i234.me,https://api.linusk.i234.me

# Start the server
CMD ["node", "server.js"]
