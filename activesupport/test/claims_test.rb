require 'abstract_unit'

class ClaimsTest < ActiveSupport::TestCase

  def test_verify
    claims = { pld: "data", for: "test", exp: "2021-12-31T18:30:00.000Z" }
    assert_equal claims[:pld], ActiveSupport::Claims.verify!(claims, { for: "test" })
  end

  def test_verify_exception_on_invalid_purpose
    claims = { pld: "data", for: "test", exp: "2021-12-31T18:30:00.000Z" }
    assert_raise(ActiveSupport::Claims::InvalidClaims) do
      ActiveSupport::Claims.verify!(claims, { for: "different_purpose" })
    end
  end

  def test_verify_exception_on_invalid_expiry
    claims = { pld: "data", for: "test", exp: "2010-12-31T18:30:00.000Z" }
    options = { for: "test" }
    assert_raise(ActiveSupport::Claims::ExpiredClaims) do
      ActiveSupport::Claims.verify!(claims, options)
    end
  end
end
