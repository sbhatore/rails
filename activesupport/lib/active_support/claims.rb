require 'active_support/time'

module ActiveSupport  
  class Claims
    class InvalidClaims < StandardError; end
    class ExpiredClaims < StandardError; end
    
    attr_reader :payload, :purpose, :expires

    def initialize(options)
      @payload = options.fetch(:value)
      @purpose = self.class.pick_purpose(options)
      @expires = self.class.pick_expiration(options)
    end

    class << self
      def pick_purpose(options)
        options.fetch(:for) { 'universal' }
      end

      def pick_expiration(options)
        return options[:expires] if options.key?(:expires)
      end

      def verify!(claims, options = {})
        raise InvalidClaims if claims[:for] != pick_purpose(options)
        claims[:pld] if parse_expiration(claims[:exp])
      end

      private
        def parse_expiration(expiration)
          return true unless expiration

          Time.iso8601(expiration).tap do |timestamp|
            raise ExpiredClaims if Time.now.utc > timestamp
          end
        end
    end

    def to_h
      { pld: @payload, for: @purpose.to_s }.tap do |claims|
        claims[:exp] = @expires.utc.iso8601(3) if @expires
      end
    end
  end
end
