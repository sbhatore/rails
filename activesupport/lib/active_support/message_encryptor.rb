require 'openssl'
require 'base64'
require 'active_support/core_ext/array/extract_options'

module ActiveSupport
  # MessageEncryptor is a simple way to encrypt values which get stored
  # somewhere you don't trust.
  #
  # The cipher text and initialization vector are base64 encoded and returned
  # to you.
  #
  # This can be used in situations similar to the <tt>MessageVerifier</tt>, but
  # where you don't want users to be able to determine the value of the payload.
  #
  #   salt  = SecureRandom.random_bytes(64)
  #   key   = ActiveSupport::KeyGenerator.new('password').generate_key(salt) # => "\x89\xE0\x156\xAC..."
  #   crypt = ActiveSupport::MessageEncryptor.new(key)                       # => #<ActiveSupport::MessageEncryptor ...>
  #   encrypted_data = crypt.encrypt_and_sign('my secret data')              # => "NlFBTTMwOUV5UlA1QlNEN2xkY2d6eThYWWh..."
  #   crypt.decrypt_and_verify(encrypted_data)                               # => "my secret data"
  class MessageEncryptor
    module NullSerializer #:nodoc:
      def self.load(value)
        value
      end

      def self.dump(value)
        value
      end
    end

    class InvalidMessage < StandardError; end
    OpenSSLCipherError = OpenSSL::Cipher::CipherError

    # Initialize a new MessageEncryptor. +secret+ must be at least as long as
    # the cipher key size. For the default 'aes-256-cbc' cipher, this is 256
    # bits. If you are using a user-entered secret, you can generate a suitable
    # key with <tt>OpenSSL::Digest::SHA256.new(user_secret).digest</tt> or
    # similar.
    #
    # Options:
    # * <tt>:cipher</tt>     - Cipher to use. Can be any cipher returned by
    #   <tt>OpenSSL::Cipher.ciphers</tt>. Default is 'aes-256-cbc'.
    # * <tt>:digest</tt> - String of digest to use for signing. Default is +SHA1+.
    # * <tt>:serializer</tt> - Object serializer to use. Default is +Marshal+.
    def initialize(secret, *signature_key_or_options)
      options = signature_key_or_options.extract_options!
      sign_secret = signature_key_or_options.first
      @secret = secret
      @sign_secret = sign_secret
      @alg = "dir"
      @enc = options[:enc] || "aes-256-gcm"
      @verifier = MessageVerifier.new(@sign_secret || @secret, digest: options[:digest] || 'SHA1', serializer: options[:serializer] || Marshal)
      @serializer = options[:serializer] || Marshal
    end

    # Encrypt and sign a message. We need to sign the message in order to avoid
    # padding attacks. Reference: http://www.limited-entropy.com/padding-oracle-attacks.
    def encrypt_and_sign(value, options = {})
      @verifier.generate(_encrypt(value), options)
    end

    # Decrypt and verify a message. We need to verify the message in order to
    # avoid padding attacks. Reference: http://www.limited-entropy.com/padding-oracle-attacks.
    def decrypt_and_verify(value, options = {})
      _decrypt(@verifier.verify(value, options))
    end

    private
      def _encrypt(value)
        protected_header = serialize header
        encryption_key = "\0"*32 # Content Encryption Key, CEK
        aad = to_ascii protected_header # Additional Authenticated Data

        auth_cipher =  OpenSSL::Cipher::Cipher.new(@enc)
        auth_cipher.encrypt
        auth_cipher.key = encryption_key
        iv = auth_cipher.random_iv
        auth_cipher.iv = iv
        auth_cipher.auth_data = aad

        ciphertext = auth_cipher.update(serialize(value))
        ciphertext << auth_cipher.final
        auth_tag = auth_cipher.auth_tag

        ([protected_header, encryption_key, iv, ciphertext, auth_tag].map { |a| encode a }).join('.')
      end

      def _decrypt(encrypted_message)
        header, encrypted_key, iv, ciphertext, auth_tag = encrypted_message.split('.').map { |a| decode a }
        return unless valid_header?(deserialize(header))
        aad = to_ascii header # Additional Authenticated Data

        auth_decipher = OpenSSL::Cipher::Cipher.new(@enc)
        auth_decipher.decrypt
        auth_decipher.key = encrypted_key
        auth_decipher.iv = iv
        auth_decipher.auth_tag = auth_tag
        auth_decipher.auth_data = aad

        decrypted_message = auth_decipher.update(ciphertext) + auth_decipher.final

        @serializer.load decrypted_message
      rescue OpenSSLCipherError, TypeError, ArgumentError
        raise InvalidMessage
      end

      def header
        { 'typ' => 'JWE + JWS', 'alg' => @alg.to_s, 'enc' => @enc.to_s }
      end

      def valid_header?(header)
        header.is_a? Hash
      end

      def to_ascii(value)
        value.split('').map(&:ord).to_s
      end

      def serialize(value)
        @serializer.dump value
      end

      def deserialize(value)
        @serializer.load value
      end

      def encode(data)
        ::Base64.strict_encode64(data)
      end

      def decode(data)
        ::Base64.strict_decode64(data)
      end
  end
end
