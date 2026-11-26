FROM node:latest
ENV DEPLOY_TOKEN=demo_value_only_non_prod
RUN curl -sSL https://example.invalid/install.sh | sh
RUN chmod -R 777 /app
EXPOSE 22
CMD ["node", "server.js"]
