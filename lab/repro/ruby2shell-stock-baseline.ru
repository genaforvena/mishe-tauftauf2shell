# Stock classic Sinatra exposure baseline. No routes or application middleware:
# Rack::MethodOverride processes the multipart _method part before the default
# 404 response. Bind/port are the only lab-specific settings.
gem 'sinatra', '4.2.2'
gem 'rack', '3.2.8'
gem 'rackup', '2.3.1'
gem 'webrick', '1.9.2'
require 'sinatra'
set :bind, '127.0.0.1'
set :port, ENV.fetch('RUBY2SHELL_STOCK_PORT', '4550').to_i
