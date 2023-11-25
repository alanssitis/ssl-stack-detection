# Dockerfile

# Use the official Nginx image
FROM nginx:latest

# Remove default Nginx configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/

# Copy SSL certificate and key
COPY server.crt /etc/nginx/conf.d/
COPY server.key /etc/nginx/conf.d/

# Expose HTTPS port
EXPOSE 443

# Command to run Nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]

