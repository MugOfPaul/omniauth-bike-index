require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class BikeIndex < OmniAuth::Strategies::OAuth2


      option :name, :bike_index
      option :client_options, { :site          => 'https://bikeindex.org',
                                :authorize_url => '/oauth/authorize' }

      option :scope, 'public'
      

      uid { raw_info['id'] }

      info do
        hash = {}

        unless raw_info['bike_ids'].nil? || raw_info['bike_ids'] == 0
          hash['bike_ids'] = raw_info['bike_ids'] 
        end
        
        unless raw_info['user'].nil? || raw_info['user'] == 0
          hash['nickname']  = raw_info['user']['username']
          hash['email']     = raw_info['user']['email']
          hash['name']      = raw_info['user']['name']
          hash['twitter']   = raw_info['user']['twitter']
          hash['image']     = raw_info['user']['image']
        end

        prune! hash
      end

      extra do
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        @raw_info ||= access_token.get('/api/v2/me').parsed || {}
      end

      def authorize_params
        options.authorize_params[:scope] = options.scope
        super
      end

      def callback_url
        if @authorization_code_from_signed_request_in_cookie
          ''
        else
          options[:callback_url] || (full_host + script_name + callback_path)
        end
      end

    private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

    end
  end
end