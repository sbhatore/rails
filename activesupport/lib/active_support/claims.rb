require 'active_support/time'

module ActiveSupport  
  class Claims
    class InvalidClaims < StandardError; end
    class ExpiredClaims < StandardError; end
    
    attr_reader :payload, :purpose, :expires
    alias_method :expires_at, :expires

    def initialize(options)
      @payload = options.fetch(:value)
      @purpose = self.class.pick_purpose(options)
      @expires = pick_expiration(options)
    end

    class << self
      attr_accessor :expires_in

      def pick_purpose(options)
        options.fetch(:for) { 'universal' }
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

    def ==(other)
      other.is_a?(self.class) && @purpose == other.purpose && @payload == other.payload
    end

    private
      def pick_expiration(options)
        return options[:expires] || options[:expires_at] if options.key?(:expires) || options.key?(:expires_at)

        if expires_in = options.fetch(:expires_in) { self.class.expires_in }
          expires_in.from_now
        end
      end
  end
end