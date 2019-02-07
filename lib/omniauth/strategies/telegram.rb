# frozen_string_literal: true

require 'omniauth'
require 'openssl'
require 'base64'
require 'ostruct'

module OmniAuth
  module Strategies
    class Telegram
      include OmniAuth::Strategy

      DEFAULT_SETTINGS = {
        'request_phase_title' => 'Telegram Login',
        'request_access' => false,
        'button_script_url' => 'https://telegram.org/js/telegram-widget.js?5',
        'auth_date_limit' => 86400
      }.freeze

      args %w[bot_name secret]

      option :name, 'telegram'
      option :bot_name, nil
      option :secret, nil
      option :button_config, {}
      option :settings, {}

      REQUIRED_FIELDS = %w[id first_name last_name auth_date hash].freeze

      def request_phase
        button_data_attrs = options.button_config.map { |k,v| "data-#{k.sub('_', '-')}=\"#{v}\"" }
        button_data_attrs << 'data-request-access="write"' if settings.request_access

        html = <<-HTML
          <!DOCTYPE html>
          <html>
          <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <title>#{settings.request_phase_title}</title>
          </head>
          <body>
            <script
              async
              src="#{settings.button_script_url}"
              data-telegram-login="#{options.bot_name}"
              data-auth-url="#{callback_url}"
              #{button_data_attrs.join(' ')}
            >
            </script>
          </body>
          </html>
        HTML

        Rack::Response.new(html, 200, 'content-type' => 'text/html').finish
      end

      def callback_phase
        valid, error = validate_request_params(request.params)
        if valid
          super
        else
          fail!(error)
        end
      end

      uid do
        request.params['id']
      end

      info do
        params = request.params
        {
          name:       "#{params['first_name']} #{params['last_name']}",
          nickname:   params['username'],
          first_name: params['first_name'],
          last_name:  params['last_name'],
          image:      params['photo_url']
        }
      end

      extra do
        {
          auth_date: Time.at(request.params['auth_date'].to_i)
        }
      end

      private

      def settings
        @settings ||= OpenStruct.new(DEFAULT_SETTINGS.merge(options.settings.to_h))
      end

      def valid_signature?
        params = request.params.dup

        hash = params.delete('hash')
        data = params.map { |key, value| "#{key}=#{value}" }.sort.join("\n")

        secret_digest = OpenSSL::Digest::SHA256.digest(options.secret)
        hashed_signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, secret_digest, data)

        hash == hashed_signature
      end

      def validate_request_params(params)
        missing_fields = REQUIRED_FIELDS.each do |field|
          return [false, :missing_required_field] if params[field].to_s.length == 0
        end
        return [false, :signature_mismatch] unless valid_signature?
        return [false, :session_expired] if Time.now.to_i - params['auth_date'].to_i > settings.auth_date_limit

        true
      end
    end
  end
end
