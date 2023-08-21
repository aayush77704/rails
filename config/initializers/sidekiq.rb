require 'sidekiq'

Sidekiq.configure_server do |config|
  config.redis = { url: ENV['REDIS_URL'], network_timeout: 5 }
  config.average_scheduled_poll_interval = 1
  config.redis_namespace = 'sidekiq'
  config.logger.level = Logger::INFO
end

Sidekiq.configure_client do |config|
  config.redis = { url: ENV['REDIS_URL'], network_timeout: 5 }
end