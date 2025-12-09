# Multi-stage Dockerfile for JavaScript API Automation
# Stage 1: Base image with Node.js
FROM node:18-alpine AS base

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Stage 2: Dependencies
FROM base AS dependencies

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Stage 3: Development dependencies
FROM base AS development

# Install all dependencies (including dev)
RUN npm ci && npm cache clean --force

# Copy source code
COPY . .

# Stage 4: Testing
FROM development AS testing

# Run tests
RUN npm run test:coverage

# Stage 5: Production
FROM base AS production

# Copy production dependencies
COPY --from=dependencies /app/node_modules ./node_modules

# Copy source code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S api-automation -u 1001

# Change ownership
RUN chown -R api-automation:nodejs /app
USER api-automation

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
