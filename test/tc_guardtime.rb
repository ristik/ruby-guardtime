require './guardtime'
require 'digest/sha2'
require 'test/unit'

class TestGuardTime < Test::Unit::TestCase

  def test_old
    ts = File.open( File.dirname(__FILE__) + File::SEPARATOR + 'cat.gif.gtts', 'rb' ) do |f|
        f.read
    end
  	gt3 = GuardTime.new
  	assert( gt3.verify(ts) )
    assert_raise ArgumentError do
        gt3.verify("corrupted signature token")
    end
    assert_block do
        gt3.verify(ts) do |r|
    		assert_instance_of(Time, r[:time])
    		assert(Time.now - r[:time] > 60*60*24*45, 'must be old sig')
        	assert_equal( GuardTime::PUBLICATION_CHECKED | GuardTime::PUBLICATION_REFERENCE_PRESENT,
        				 r[:verification_status])
        	assert_equal( GuardTime::NO_FAILURES, r[:verification_errors])
    		assert_instance_of( Array, r[:pub_reference_list])
    		assert_instance_of( String, r[:publication_string])
    		assert_instance_of(Time, r[:publication_time])
        	r[:verification_errors] == GuardTime::NO_FAILURES
        end
    end
    h3 = Digest::SHA2.new << File.read(File.dirname(__FILE__) + File::SEPARATOR + 'cat.gif')
    assert( gt3.verify(ts, h3) )    
    assert( gt3.verify(ts, h3) do |r|
    	assert_equal( GuardTime::PUBLICATION_CHECKED | GuardTime::PUBLICATION_REFERENCE_PRESENT | 
    				GuardTime::DOCUMENT_HASH_CHECKED, r[:verification_status])
		assert_equal(h3.hexdigest, r[:hash_value].delete(':'))
    	r[:verification_errors] == GuardTime::NO_FAILURES
      end
    )
    # extending token first, then verifying
    assert( tsext = gt3.extend(ts) )
    gt4 = GuardTime.new({:loadpubs => 'once', :verifieruri => ''})
    gt4.verify(tsext, h3) do |r|
        assert_equal( GuardTime::PUBLICATION_CHECKED | GuardTime::PUBLICATION_REFERENCE_PRESENT | 
                    GuardTime::DOCUMENT_HASH_CHECKED, r[:verification_status])
    end
    # verification without extending
    gt4.verify(ts, h3) do |r|
        assert_equal( GuardTime::PUBLICATION_CHECKED | GuardTime::PUBLIC_KEY_SIGNATURE_PRESENT |
                    GuardTime::DOCUMENT_HASH_CHECKED, r[:verification_status])
    end


  end

  def test_fresh
	h = Digest::SHA2.new(256) << 'bla bla blah'
	gt = GuardTime.new
	assert_instance_of(GuardTime, gt)
	ts = gt.sign(h)
    assert_equal('SHA256', GuardTime.gethashalg(ts).upcase, 'GuardTime.gethashalg() works')

    assert_raise TypeError do
        GuardTime.gethashalg(123)
    end
    assert_raise RuntimeError do
        GuardTime.gethashalg("corrupted signature token")
    end
    assert_raise RuntimeError do
        GuardTime.getnewdigester("corrupted signature token")
    end
    h2 = GuardTime.getnewdigester(ts) << 'bla bla blah'
    assert_equal(h.inspect, h2.inspect, 'GuardTime.getnewdigester()')
    assert( gt.verify(ts) do |r|
    	assert_equal( GuardTime::PUBLIC_KEY_SIGNATURE_PRESENT | GuardTime::PUBLICATION_CHECKED, 
    					r[:verification_status])
    	assert_equal( GuardTime::NO_FAILURES, r[:verification_errors])
		assert_equal( nil, r[:pub_reference_list])
		assert_equal( nil, r[:publication_string])
		assert_instance_of(Time, r[:time])
		assert(Time.now - r[:time] < 60, 'local wall clock may be out of sync?')
		assert_instance_of(Time, r[:publication_time])
		assert_equal(h.hexdigest, r[:hash_value].delete(':'))
		assert_equal('GT : GT : public', r[:location_name])
    	r[:verification_errors] == GuardTime::NO_FAILURES
    end
    )
    assert( gt.verify(ts, h2))
    assert( gt.verify(ts, h2) do |r|
    	assert_equal( GuardTime::PUBLIC_KEY_SIGNATURE_PRESENT | GuardTime::PUBLICATION_CHECKED | 
    				GuardTime::DOCUMENT_HASH_CHECKED, r[:verification_status])
    	r[:verification_errors] == GuardTime::NO_FAILURES
    end
    )

    assert(gt.verify(ts, 'SHA256', h2.digest))

    gt2 = GuardTime.new({:loadpubs => 'no', :verifieruri => ''})
    assert( gt2.verify(ts) do |r|
    	assert_equal( GuardTime::PUBLIC_KEY_SIGNATURE_PRESENT, r[:verification_status])
    	r[:verification_errors] == GuardTime::NO_FAILURES
    end
    )
    assert( gt2.verify(ts, h2) do |r|
    	assert_equal( GuardTime::PUBLIC_KEY_SIGNATURE_PRESENT | GuardTime::DOCUMENT_HASH_CHECKED, r[:verification_status])
    	r[:verification_errors] == GuardTime::NO_FAILURES
    end
    )

    wrongh = Digest::SHA2.new << 'whateverelse'
    assert_equal( false, gt2.verify(ts, wrongh) )
    assert_equal( false, gt2.verify(ts, wrongh) do |r|
    	assert_equal( GuardTime::PUBLIC_KEY_SIGNATURE_PRESENT | GuardTime::DOCUMENT_HASH_CHECKED, r[:verification_status])
    	assert_equal( GuardTime::WRONG_DOCUMENT_FAILURE, r[:verification_errors])
    	r[:verification_errors] == GuardTime::NO_FAILURES
    end
    )
    exception = assert_raise RuntimeError do
        ext = gt.extend(ts)
    end
    assert_match /not yet available/, exception.message
 end
 
end

