/*
 * Copyright 2013 Guardtime AS
 *
 * This file is part of the Guardtime Ruby SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "ruby.h"
#if RUBY_VERSION >= 190
#  include <ruby/st.h>
#else
#  include <st.h>
#endif
#include <time.h>
#include <gt_base.h>
#include <gt_http.h>

static VALUE rb_cGuardTime;

#define DEFAULT_SIGNERURI   "http://stamper.guardtime.net/gt-signingservice"
#define DEFAULT_VERIFIERURI "http://verifier.guardtime.net/gt-extendingservice"
#define DEFAULT_PUBFILEURI  "http://verify.guardtime.com/gt-controlpublications.bin"
#define DEFAULT_LOADPUBS    "auto"
#define PUBDATA_UPDATE_SECONDS (8 * 60 * 60)

// object instance state
typedef struct _GuardTimeData {
	const char* signeruri;
	const char* verifieruri;
	const char* pubfileuri;
	const char* loadpubs;
	time_t pubdataupdated;
	GT_Time_t64 lastpublicationtime;
	GTPublicationsFile *pub;   
} GuardTimeData;


// based on GTHTTP_verifyTimestampHash from gt_http.c, modified to support more 
//     combinations of arguments and externalized pub. file processing
static int verifyTimestamp(const GTTimestamp *ts,
		const GTDataHash *hash, GuardTimeData *gt, 
		int parse, GTVerificationInfo **ver)
{
	int res = GT_UNKNOWN_ERROR;
	GTVerificationInfo *ver_tmp = NULL;
	GTTimestamp *ext = NULL;
	int is_ext = 0, is_new = 0;

	if (ts == NULL || ver == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Check internal consistency of the timestamp. */
	res = GTTimestamp_verify(ts, parse, &ver_tmp);
	if (res != GT_OK) {
		goto cleanup;
	}
	if (ver_tmp == NULL || ver_tmp->implicit_data == NULL) {
		res = GT_UNKNOWN_ERROR;
		goto cleanup;
	}
	if (ver_tmp->verification_errors != GT_NO_FAILURES) {
		goto cleanup;
	}

	/* Check document hash.
	 * GT_WRONG_DOCUMENT means the hash did not match.
	 * Everything else is some sort of system error. */
	if (hash != NULL) {
		res = GTTimestamp_checkDocumentHash(ts, hash);
		if (res == GT_OK) {
			ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
		} else if (res == GT_WRONG_DOCUMENT) {
			ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
			ver_tmp->verification_errors |= GT_WRONG_DOCUMENT_FAILURE;
			res = GT_OK;
			goto cleanup;
		} else {
			goto cleanup;
		}
	}

	/* Whether the timestamp is extended. */
	is_ext = ((ver_tmp->verification_status & GT_PUBLIC_KEY_SIGNATURE_PRESENT) == 0);
	/* Whether it is too new to be extended. */
	is_new = (ver_tmp->implicit_data->registered_time > gt->lastpublicationtime);

	/* If the timestamp is already extended, "promote" it.
	 * If it is not extended, but is old enough, attempt to extend it. */
	if (is_ext) {
		ext = (GTTimestamp *) ts;
	} else if (!is_new && gt->verifieruri != NULL) {
		res = GTHTTP_extendTimestamp(ts, gt->verifieruri, &ext);
		/* If extending fails because of infrastructure failure, fall
		 * back to signing key check. Else report errors. */
		if (res == GT_NONSTD_EXTEND_LATER || res == GT_NONSTD_EXTENSION_OVERDUE ||
				(res >= GTHTTP_IMPL_BASE && res <= GTHTTP_HIGHEST)) {
			res = GT_OK;
		}
		if (res != GT_OK) {
			goto cleanup;
		}
	}

	/* If we now have a new timestamp, check internal consistency and document hash. */
	if (ext != NULL && ext != ts) {
		/* Release the old verification info. */
		GTVerificationInfo_free(ver_tmp);
		ver_tmp = NULL;
		/* Re-check consistency. */
		res = GTTimestamp_verify(ext, parse, &ver_tmp);
		if (res != GT_OK) {
			goto cleanup;
		}
		if (ver_tmp == NULL || ver_tmp->implicit_data == NULL) {
			res = GT_UNKNOWN_ERROR;
			goto cleanup;
		}
		if (ver_tmp->verification_errors != GT_NO_FAILURES) {
			goto cleanup;
		}
		/* Re-check document hash. */
		if (hash != NULL) {
			res = GTTimestamp_checkDocumentHash(ts, hash);
			if (res == GT_OK) {
				ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
			} else if (res == GT_WRONG_DOCUMENT) {
				ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
				ver_tmp->verification_errors |= GT_WRONG_DOCUMENT_FAILURE;
				res = GT_OK;
				goto cleanup;
			} else {
				goto cleanup;
			}
		}
	}
	if (gt->pub != NULL) {
		if (ext != NULL) {
			/* If we now have an extended timestamp, check publication.
			 * GT_TRUST_POINT_NOT_FOUND and GT_INVALID_TRUST_POINT mean it did not match.
			 * Everything else is some sort of system error. */
			res = GTTimestamp_checkPublication(ext, gt->pub);
			if (res == GT_OK) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
			} else if (res == GT_TRUST_POINT_NOT_FOUND || res == GT_INVALID_TRUST_POINT) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
				ver_tmp->verification_errors |= GT_NOT_VALID_PUBLICATION;
				res = GT_OK;
			}
		} else {
			/* Otherwise, check signing key.
			 * GT_KEY_NOT_PUBLISHED and GT_CERT_TICKET_TOO_OLD mean key not valid.
			 * Everything else is some sort of system error. */
			res = GTTimestamp_checkPublicKey(ts, ver_tmp->implicit_data->registered_time, gt->pub);
			if (res == GT_OK) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
			} else if (res == GT_KEY_NOT_PUBLISHED || res == GT_CERT_TICKET_TOO_OLD) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
				ver_tmp->verification_errors |= GT_NOT_VALID_PUBLIC_KEY_FAILURE;
				res = GT_OK;
			}
		}
	}

cleanup:
	if (res == GT_OK) {
		*ver = ver_tmp;
		ver_tmp = NULL;
	}
	if (ext != ts)
		GTTimestamp_free(ext);
	GTVerificationInfo_free(ver_tmp);

	return res;
}

static void get_gtdatahash(VALUE digest, GTDataHash *dh)
{
	int gtalgoid;
	const char * cn = rb_obj_classname(digest); // Digest::SHA2
	VALUE rb_digest = rb_funcall(digest, rb_intern("digest"), 0);
	int bitlen = 8 * NUM2INT(rb_funcall(digest, rb_intern("digest_length"), 0));

	gtalgoid = (
		strcasecmp(cn, "Digest::SHA1") == 0 ? GT_HASHALG_SHA1 :
			strcasecmp(cn, "Digest::SHA2") == 0 ? 
				(bitlen == 224 ? GT_HASHALG_SHA224 :
					bitlen == 256 ? GT_HASHALG_SHA256 :
					bitlen == 384 ? GT_HASHALG_SHA384 :
					bitlen == 512 ? GT_HASHALG_SHA512 : -1
				):
			strcasecmp(cn, "Digest::RMD160") == 0 ? GT_HASHALG_RIPEMD160 : -1
		);
	if (gtalgoid < 0)
		rb_raise(rb_eArgError, "Argument must be supported Digest::... instance.");

	dh->context = NULL;
	dh->algorithm = gtalgoid;
	dh->digest = (unsigned char *)RSTRING_PTR(rb_digest);
	dh->digest_length = RSTRING_LEN(rb_digest);
}

static void get_gtdatahash2(VALUE algo, VALUE digest, GTDataHash *dh)
{
	int gtalgoid;
	StringValue(algo);
	StringValue(digest);
	gtalgoid = (
		  strcasecmp(RSTRING_PTR(algo), "sha1") == 0 ? GT_HASHALG_SHA1 :
		  strcasecmp(RSTRING_PTR(algo), "sha224") == 0 ? GT_HASHALG_SHA224 :
		  strcasecmp(RSTRING_PTR(algo), "sha256") == 0 ? GT_HASHALG_SHA256 :
		  strcasecmp(RSTRING_PTR(algo), "sha384") == 0 ? GT_HASHALG_SHA384 :
		  strcasecmp(RSTRING_PTR(algo), "sha512") == 0 ? GT_HASHALG_SHA512 :
		  strcasecmp(RSTRING_PTR(algo), "ripemd160") == 0 ? GT_HASHALG_RIPEMD160 :
		  -1);
	if (gtalgoid < 0)
		rb_raise(rb_eArgError, "Argument must be supported Digest::... instance.");

	dh->context = NULL;
	dh->algorithm = gtalgoid;
	dh->digest = (unsigned char *)RSTRING_PTR(digest);
	dh->digest_length = RSTRING_LEN(digest);
}

/* 
 * call-seq: 
 *		sign(Digest) -> signature_token
 *		sign(hashalgname, binarydigest) -> signature_token
 *
 * * *Args*    :
 *   - +Digest+ -> Digest object, implementing supported hahs algorithm, encapsulating already calculated hash value.
 *		example: guardtime.sign(Digest.SHA2.new(256).update('this string shall be signed'))
 *   - +hashalgname+ -> String with OpenSSL style hash algorithm name, either SHA256, SHA224, SHA384, SHA512, SHA1 or RIPEMD160.
 *   - +binarydigest+ -> String with binary hash value.
 * * *Returns* :
 *   - String containing binary data with Guardime signature token. May be directly saved etc.
 * * *Raises* :
 *   - +ArgumentError+ -> if any value is nil or wrong type.
 *   - +RuntimeError+ -> other errors, including network, hash value etc.
 */
static VALUE
guardtime_sign(int argc, VALUE *argv, VALUE obj)
{
	int res;
	GTDataHash dh;
	GTTimestamp *ts;
	unsigned char *data;
	size_t data_length;
	GuardTimeData *gt;
	VALUE hash, hash2, result;

	switch (rb_scan_args(argc, argv, "11", &hash, &hash2)) {
		case 1:
			get_gtdatahash(hash, &dh);
			break;
		case 2:
			get_gtdatahash2(hash, hash2, &dh);
			break;
	}
	Data_Get_Struct(obj, GuardTimeData, gt);
	res = GTHTTP_createTimestampHash(&dh, gt->signeruri, &ts);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GTHTTP_getErrorString(res));

	res = GTTimestamp_getDEREncoded(ts, &data, &data_length);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));
	GTTimestamp_free(ts);
	result = rb_str_new((char*)data, data_length);
	GT_free(data);
	return result;
}

/* 
 * call-seq: 
 *		extend(sig) -> extended_signature_token
 *
 * * *Args*    :
 *   - +sig+ -> String containing binary data with Guardime signature token. May be directly loaded from file.
 * * *Returns* :
 *   - String containing binary data with Guardime signature token. May be directly saved etc.
 * * *Raises* :
 *   - +ArgumentError+ -> if any value is nil or wrong type.
 *   - +RuntimeError+ -> other errors, including network, hash value, token too new or old etc. Proper description is in the error message.
 * Extended signature token may be used for 'independent' verification without any keys or services. Just data, token and newspaper with published value.
 * There is no point in extending new signature before next newspaper publication is performed. Good rule of thumb is to wait for 35 days (after signing), or until 15th date plus 5 more days.
 */
static VALUE
guardtime_extend(VALUE obj, VALUE in)
{
	int res;
	GTTimestamp *ts, *ts2;
	unsigned char *data;
	size_t data_length;
	GuardTimeData *gt;
	VALUE result;

	StringValue(in);
	Data_Get_Struct(obj, GuardTimeData, gt);
	res = GTTimestamp_DERDecode(RSTRING_PTR(in), 
						RSTRING_LEN(in), &ts);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));

	res = GTHTTP_extendTimestamp(ts, gt->verifieruri, &ts2);
	GTTimestamp_free(ts);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GTHTTP_getErrorString(res));

	res = GTTimestamp_getDEREncoded(ts2, &data, &data_length);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));

	result = rb_str_new((char*)data, data_length);
	GT_free(data);
	return result;
}

// load and parse/verify pub. file, populate state.
int loadpubs_helper(GuardTimeData *gt) {
	int res = GT_OK;
	GTPubFileVerificationInfo *pub_ver;

	if (gt->pub != NULL)
		GTPublicationsFile_free(gt->pub);		
	res = GTHTTP_getPublicationsFile(gt->pubfileuri, &(gt->pub));
	if (res == GT_OK)
		res = GTPublicationsFile_verify(gt->pub, &pub_ver);
	if (res == GT_OK) {
		gt->lastpublicationtime = pub_ver->last_publication_time;
		GTPubFileVerificationInfo_free(pub_ver);
	}
	return res;
}

static void loadpubs(VALUE self)
{
	int res = GT_OK;
	time_t now;
	GuardTimeData *gt;
	Data_Get_Struct(self, GuardTimeData, gt);

	if (strcasecmp(gt->loadpubs, "auto") == 0) {
		time(&now);
		if (now <= gt->pubdataupdated + PUBDATA_UPDATE_SECONDS)
			return;
		res = loadpubs_helper(gt);
		if (res == GT_OK)
			gt->pubdataupdated = now;
	} 
	else if (strcasecmp(gt->loadpubs, "once") == 0) {
		if (gt->pub != NULL)
			return;
		res = loadpubs_helper(gt);
	}
	else if (strcasecmp(gt->loadpubs, "always") == 0) {
		res = loadpubs_helper(gt);
	}
	else if (strcasecmp(gt->loadpubs, "no") == 0) {
		return;
	}
	else
		rb_raise(rb_eArgError, "'loadpubs' parameter must be either 'auto', 'once', 'no', or 'always'");	

	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "Error downloading/validating publishing data: %s", GTHTTP_getErrorString(res));	
}

static VALUE 
gttime_to_rubyTime(GT_Time_t64 t) 
{
	VALUE ruby_cTime, rubytime;
	if (t == 0)
		return Qnil;
	ruby_cTime = rb_const_get(rb_cObject, rb_intern("Time"));
	rubytime = rb_funcall(ruby_cTime, rb_intern("at"), 1, ULL2NUM(t));
	return rubytime;
}

static VALUE
format_location_id(GT_UInt64 l)
{
	char buf[32];
	if (l == 0)
		return Qnil;
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
					(unsigned) (l >> 48 & 0xffff),
					(unsigned) (l >> 32 & 0xffff),
					(unsigned) (l >> 16 & 0xffff),
					(unsigned) (l & 0xffff));	
	return rb_str_new2(buf);  //yes, makes copy.
}

static VALUE
format_hash_algorithm(int alg)
{
	switch(alg) {  
		case GT_HASHALG_SHA256: 
			return rb_str_new2("SHA256");
		case GT_HASHALG_SHA1: 
			return rb_str_new2("SHA1");
		case GT_HASHALG_RIPEMD160: 
			return rb_str_new2("RIPEMD160");
		case GT_HASHALG_SHA224: 
			return rb_str_new2("SHA224");
		case GT_HASHALG_SHA384: 
			return rb_str_new2("SHA384");
		case GT_HASHALG_SHA512: 
			return rb_str_new2("SHA512");
		default:
			return Qnil;
	}
}

/* 
 * call-seq:
 *		verify(sig) -> true/false
 *		verify(sig, Digest) -> true/false
 *		verify(sig, hashalgname, binarydigest) -> true/false
 *		verify(sig, ...) {|resulthash| ... statement }  -> value_of_last_cb_statement
 *
 * * *Args*    :
 *   - +sig+ -> String containing binary data with Guardime signature token. May be directly loaded from file.
 *   - +Digest+ -> Digest object, implementing supported hash algorithm, encapsulating already calculated hash value. 
 *   - +hashalgname+ -> String with OpenSSL style hash algorithm name, either SHA256, SHA224, SHA384, SHA512, SHA1 or RIPEMD160.
 *   - +binarydigest+ -> String with binary hash value. Obtain with +Digest.digest+ for example.
 *   - +code_block+   -> Optional code block serves two purposes: 1) Allows to implement _verification_policies_, i.e. add additional checks to the signature verification, and 2) Gives access to signature properties present in code block argument +resulthash+.
 * * *Returns* :
 *   - either +true+ or +false+, depending on the result of verification. If code block is used then the value returned by last statement of code block is passed through.
 * * *Raises* :
 *   - +ArgumentError+ -> if any value is nil or wrong type, or signature token is corrupted.
 *   - +RuntimeError+ -> other errors, including network, hash value etc.
 * 
 * Code block receives parameter +resulthash+ which is populated with verified signature properties. There are following keys:
 * *verification_errors*::	bitfield containing verification errors. See class constants. Verification is successful only if value equals to <tt>GuardTime::NO_FAILURES</tt>
 * *verification_status*::	Numeric bitfield -- flags identifying successful verification checks. See class constants.
 * *time*::				Time object containing signing (time-stamp) datum.
 * *registered_time*::	Numeric containing 'time_t' representation (seconds since Epoch) of the signing datum.
 * *hash_algorithm*::	String with OpenSSL style hash algorithm name; this algorithm was used for hashing the original data.
 * *hash_value*::		Hash of the signed data, formatted as String of ':'-separated hex octets.
 * *location_name*::	String containing signature issuer name within the GuardTime network. Example: 'GT : GT : Customer'
 * *location_id*::		String containing '.' separated customer address hierarchy.
 * *policy*::			String with signing/time-stamping policy OID.
 * *publication_identifier*::	Publication ID, Numeric.
 * *publication_string*::		Control string for verifying the timestamp using a hardcopy publication, the value is base32(time+alg+hash+crc32)
 * *pub_reference_list*::		Array of UTF-8 encoded Strings containing list of newspaper issues or other media used for publishing verification values.
 * *publication_time*::			Time object containing datum of publishing time which could be used for intependent 'newspaper based' verification.
 * *public_key_fingerprint*::	String with PKI key fingerprint which could be used for extra verification until newspaper hash-link publication becomes available. List of trusted keys is published with publications file.
 *
 * * *Notes*
 *   - hash algorithm must match one used for hashing the original data during signing. See example below.
 *   - finish the code block with <tt>resulthash[:verification_errors] == GuardTime::NO_FAILURES</tt> if You care of the return value!
 *
 * * *Examples*
 *   - Default behaviour (without code block) is acheved with following code: 
 *        result = guardtime_obj.verify(token) do |resulthash|
 * 		 		resulthash[:verification_errors] == GuardTime::NO_FAILURES
 *        end
 *   - Verification flow with loading token, determining hash alg., hashing file, verifying with signer ID check.
 *        token = slurpbinaryfile('importantdata.txt.gtts')
 *        hasher = GuardTime.getnewdigester(token)
 *        hasher << slurpbinaryfile('importantdata.txt')
 *        gt = GuardTime.new
 *        signedAt = nil
 *        okay = gt.verify(token, hasher) do |r|
 *              signedAt = r[:time]
 *              /companyname$/ =~ r[:location_name] and 
 * 		 		   r[:verification_errors] == GuardTime::NO_FAILURES
 *        end
 *        puts "data signed at #{signedAt.utc.to_s}" if okay
 */
static VALUE
guardtime_verify(int argc, VALUE *argv, VALUE obj)
{
	int res, argcount;
	GTTimestamp *ts;
	GTDataHash dh;
	GuardTimeData *gt;
	VALUE tsdata, hash, hash2, block, retval;
	GTVerificationInfo *verification_info = NULL;
	Data_Get_Struct(obj, GuardTimeData, gt);

	argcount = rb_scan_args(argc, argv, "12&", &tsdata, &hash, &hash2, &block);
	StringValue(tsdata);

	res = GTTimestamp_DERDecode(RSTRING_PTR(tsdata), 
						RSTRING_LEN(tsdata), &ts);
	if (res != GT_OK)
		rb_raise(rb_eArgError, "%s", GT_getErrorString(res));

	loadpubs(obj);
	switch (argcount) {
		case 1:
			res = verifyTimestamp(ts, NULL, gt, RTEST(block)? 1:0, &verification_info);
			break;
		case 2:
			get_gtdatahash(hash, &dh);
			res = verifyTimestamp(ts, &dh, gt, RTEST(block)? 1:0, &verification_info);
			break;
		case 3:
			get_gtdatahash2(hash, hash2, &dh);
			res = verifyTimestamp(ts, &dh, gt, RTEST(block)? 1:0, &verification_info);
			break;
	}

	if (res != GT_OK) {
		GTTimestamp_free(ts);
		rb_raise(rb_eRuntimeError, "%s", GTHTTP_getErrorString(res));
	}

#define RBNILSTR(n, i) \
	(		rb_hash_aset(retval, ID2SYM(rb_intern(n)), (i) == NULL ? Qnil : rb_str_new2(i))  )
#define RBSET(n, v)    \
	(		rb_hash_aset(retval, ID2SYM(rb_intern(n)), (v))  )

	if (RTEST(block)) {
		retval = rb_hash_new();
		RBSET("verification_status", INT2FIX( verification_info->verification_status ));
		RBSET("verification_errors", INT2FIX( verification_info->verification_errors ));
		// impl
		RBSET("registered_time", ULL2NUM( verification_info->implicit_data->registered_time ));
		RBSET("location_id", 	 format_location_id( verification_info->implicit_data->location_id ));
		RBNILSTR("location_name",          verification_info->implicit_data->location_name );
		RBNILSTR("public_key_fingerprint", verification_info->implicit_data->public_key_fingerprint );
		RBNILSTR("publication_string",     verification_info->implicit_data->publication_string );
		// expl
		RBNILSTR("policy", verification_info->explicit_data->policy);
		RBSET("hash_algorithm", format_hash_algorithm( verification_info->explicit_data->hash_algorithm ));
		RBNILSTR("hash_value", verification_info->explicit_data->hash_value );
		RBSET("publication_identifier", ULL2NUM( verification_info->explicit_data->publication_identifier ));

		if (verification_info->explicit_data->pub_reference_count > 0) {
			int i;
			VALUE pubrefs = rb_ary_new2(verification_info->explicit_data->pub_reference_count);
			for (i = 0; i < verification_info->explicit_data->pub_reference_count; i++)
				rb_ary_push(pubrefs, rb_str_new2( verification_info->explicit_data->pub_reference_list[i] ));
			RBSET("pub_reference_list", pubrefs);
		} else
			RBSET("pub_reference_list", Qnil);

		RBSET("time", gttime_to_rubyTime( verification_info->implicit_data->registered_time ));
		RBSET("publication_time", gttime_to_rubyTime( verification_info->explicit_data->publication_identifier ));
	} else
		retval = verification_info->verification_errors == GT_NO_FAILURES ? Qtrue : Qfalse;

	GTTimestamp_free(ts);
	GTVerificationInfo_free(verification_info);

	if (RTEST(block))
		return rb_funcall(block, rb_intern("call"), 1, retval);
	else
		return retval;
}

/* 
 * call-seq: 
 *		GuardTime.getnewdigester(signature) -> instance_of_Digest
 *
 * * *Args*    :
 *   - +signature+ -> String containing Guardtime signature token
 * * *Returns* :
 *   - instantiated object of Digest::... implementing exactly same hashing algorithm used for hashing the original signed data.
 * * *Raises* :
 *   - +TypeError+ -> wrong argument datatype.
 *   - +RuntimeError+ -> other errors like corrupted token etc.
 */
static VALUE
guardtime_getnewdigester(VALUE self, VALUE tsdata)
{
	int res;
	int alg;
	GTTimestamp *ts;
	VALUE module_klass, args[1];

	StringValue(tsdata);

	res = GTTimestamp_DERDecode(RSTRING_PTR(tsdata), RSTRING_LEN(tsdata), &ts);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));

	res = GTTimestamp_getAlgorithm(ts, &alg);
	GTTimestamp_free(ts);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));

	// checkifnecessary: rb_requre('digest');
	module_klass = rb_const_get(rb_cObject, rb_intern("Digest"));

	switch(alg) {  
		case GT_HASHALG_SHA256: 
			args[0] = INT2FIX(256);
			return rb_class_new_instance(1, args,
					rb_const_get(module_klass, rb_intern("SHA2")));
		case GT_HASHALG_SHA1: 
			return rb_class_new_instance(0, NULL, 
					rb_const_get(module_klass, rb_intern("SHA1")));
		case GT_HASHALG_RIPEMD160:
			return rb_class_new_instance(0, NULL, 
					rb_const_get(module_klass, rb_intern("RMD160")));
		case GT_HASHALG_SHA224: 
			args[0] = INT2FIX(224);
			return rb_class_new_instance(1, args,
					rb_const_get(module_klass, rb_intern("SHA2")));
		case GT_HASHALG_SHA384:
			args[0] = INT2FIX(384);
			return rb_class_new_instance(1, args,
					rb_const_get(module_klass, rb_intern("SHA2")));
		case GT_HASHALG_SHA512:
			args[0] = INT2FIX(512);
			return rb_class_new_instance(1, args,
					rb_const_get(module_klass, rb_intern("SHA2")));
		default:
			rb_raise(rb_eRuntimeError, "%s", "Unknown hash algorithm ID");
	}
	return Qnil;
}

/* 
 * call-seq: 
 *		GuardTime.gethashalg(signature) -> algorithm_name
 *
 * * *Args*    :
 *   - +signature+ -> String containing Guardtime signature token
 * * *Returns* :
 *   - String with OpenSSL style hash algorithm name used for hashing the signed data.
 * * *Raises* :
 *   - +TypeError+ -> wrong argument datatype.
 *   - +RuntimeError+ -> other errors like corrupted token etc.
 */
static VALUE
guardtime_gethashalg(VALUE self, VALUE tsdata)
{
	int res;
	int alg;
	GTTimestamp *ts;

	StringValue(tsdata);

	res = GTTimestamp_DERDecode(RSTRING_PTR(tsdata), RSTRING_LEN(tsdata), &ts);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));

	res = GTTimestamp_getAlgorithm(ts, &alg);
	GTTimestamp_free(ts);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));

	switch(alg) {  
		case GT_HASHALG_SHA256: 
			return rb_str_new2("SHA256");
		case GT_HASHALG_SHA1: 
			return rb_str_new2("SHA1");
		case GT_HASHALG_RIPEMD160: 
			return rb_str_new2("RIPEMD160");
		case GT_HASHALG_SHA224: 
			return rb_str_new2("SHA224");
		case GT_HASHALG_SHA384: 
			return rb_str_new2("SHA384");
		case GT_HASHALG_SHA512: 
			return rb_str_new2("SHA512");
		default:
			rb_raise(rb_eRuntimeError, "Unknown hash algorithm ID");
	}
	return Qnil;
}


static int
each_conf_param(VALUE key, VALUE value, VALUE klass)
{
	ID key_id;
	GuardTimeData *gt; // = DATA_PTR(klass);
	Data_Get_Struct(klass, GuardTimeData, gt);  // typesafe macro

	if (key == Qundef) return ST_CONTINUE;
	switch(TYPE(key)) {
	case T_STRING:
		key_id = rb_intern(RSTRING_PTR(key));
		break;
	case T_SYMBOL:
		key_id = SYM2ID(key);
		break;
	default:
		rb_raise(rb_eArgError,
				 "config hash includes invalid key");
	}
	if (TYPE(value) != T_STRING)
		rb_raise(rb_eArgError,
				 "config hash value for '%s' must be a String", rb_id2name(key_id));

	if (strcasecmp(rb_id2name(key_id), "signeruri") == 0)
		gt->signeruri = RSTRING_PTR(value); // strdup() perhaps?
	else if (strcasecmp(rb_id2name(key_id), "verifieruri") == 0) {
		if (strlen(gt->verifieruri) > 0)
			gt->verifieruri = RSTRING_PTR(value);
		else
			gt->verifieruri = NULL; // no extending
	}
	else if (strcasecmp(rb_id2name(key_id), "publicationsuri") == 0)
		gt->pubfileuri = RSTRING_PTR(value);
	else if (strcasecmp(rb_id2name(key_id), "loadpubs") == 0)
		gt->loadpubs = RSTRING_PTR(value);
	else
		rb_raise(rb_eArgError,
				 "config hash has unknown key '%s'", rb_id2name(key_id));

	return ST_CONTINUE;   
}

static void
guardtime_free(GuardTimeData *gt) 
{
	if (gt) {
		if (gt->pub != NULL)
			GTPublicationsFile_free(gt->pub);
		free(gt);
	}

}

static VALUE
guardtime_allocate(VALUE self) 
{
	GuardTimeData *gt;

	gt = ALLOC(GuardTimeData);
	// DATA_PTR(self) = gt;
	gt->signeruri   = DEFAULT_SIGNERURI;
	gt->verifieruri = DEFAULT_VERIFIERURI;
	gt->pubfileuri  = DEFAULT_PUBFILEURI;
	gt->loadpubs = DEFAULT_LOADPUBS;
	gt->pub = NULL;
	gt->pubdataupdated = 0;
	return Data_Wrap_Struct(self, 0, guardtime_free, gt);
}

/* 
 * call-seq: 
 *		GuardTime.new 		-> obj
 *		GuardTime.new(confighash) -> obj
 *
 * * *Args*    :
 *   - +confighash+ -> Optional Hash containing configuration parameters. Defaults:
 *    { :signeruri =>       'http://verifier.guardtime.net/gt-extendingservice',
 *      :verifieruri =>     'http://verifier.guardtime.net/gt-extendingservice',
 *      :publicationsuri => 'http://verify.guardtime.com/gt-controlpublications.bin',
 *      :loadpubs => 'auto'
 *    }
 * 
 * * *Notes*    :
 *   - If <tt>:verifieruri</tt> is blank String then online verification is not used.
 *
 *   - <tt>:loadpubs</tt> may be either 
 *     +once+::   Publications file is loaded once.
 *     +always+:: Publications file is reloaded at each verification call
 *     +no+::     Publications file is not used for verification. May be good as token consistency check, or with extra verification (e.g. manual publication string check)
 *     +auto+::   Publications file is automatically reloaded if older than 8 hours. Default.
 * 
 *   - Please use environment to specify proxy ({syntax}[http://curl.haxx.se/docs/manpage.html#ENVIRONMENT]), Internet Explorer settints will be used on Windows. Specify url as <em>http://name:pass@site/url</em> for basic auth.
 */
static VALUE
guardtime_initialize(int argc, VALUE *argv, VALUE obj)
{	
	VALUE arghash;

	if (rb_scan_args(argc, argv, "01", &arghash) == 1)
		rb_hash_foreach(arghash, each_conf_param, obj);
	return obj;
}

/* 
 * This API provides access to the Guardtime keyless signature service.
 */
void Init_guardtime()
{
	int res;
	res = GT_init();
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GT_getErrorString(res));
	res = GTHTTP_init("ruby api 0.0.5", 1);
	if (res != GT_OK)
		rb_raise(rb_eRuntimeError, "%s", GTHTTP_getErrorString(res));

	rb_cGuardTime = rb_define_class("GuardTime", rb_cObject);
	rb_define_alloc_func(rb_cGuardTime, guardtime_allocate);
	rb_define_method(rb_cGuardTime, "initialize", guardtime_initialize, -1);
	rb_define_method(rb_cGuardTime, "sign", guardtime_sign, -1);
	rb_define_method(rb_cGuardTime, "extend", guardtime_extend, 1);
	rb_define_method(rb_cGuardTime, "verify", guardtime_verify, -1);
	rb_define_singleton_method(rb_cGuardTime, "gethashalg", guardtime_gethashalg, 1);
	rb_define_singleton_method(rb_cGuardTime, "getnewdigester", guardtime_getnewdigester, 1);

	/**
	 * \ingroup verification
	 *
	 * Timestamp verification status codes.
	 *
	 * \note The values are bit flags so that a single +int+ can contain any combination of them.
	 */	
	/* The PKI signature was present in the signature. */	
	rb_define_const(rb_cGuardTime, "PUBLIC_KEY_SIGNATURE_PRESENT", INT2NUM(GT_PUBLIC_KEY_SIGNATURE_PRESENT));
	/* Publication references (list of newspaper etc sources to verify publication value) are present in the signature. */
	rb_define_const(rb_cGuardTime, "PUBLICATION_REFERENCE_PRESENT", INT2NUM(GT_PUBLICATION_REFERENCE_PRESENT));
	/* The signature was checked against the document hash. */
	rb_define_const(rb_cGuardTime, "DOCUMENT_HASH_CHECKED", INT2NUM(GT_DOCUMENT_HASH_CHECKED));
	/* The signature was checked against the publication data. */
	rb_define_const(rb_cGuardTime, "PUBLICATION_CHECKED", INT2NUM(GT_PUBLICATION_CHECKED));

	/**
	 * \ingroup verification
	 *
	 * Signature verification error codes.
	 *
	 * \note Values other than +GT_NO_FAILURES+ are bit flags so that
	 * a single +int+ can contain any combination of them.
	 */
	/* The verification completed successfully. */
	rb_define_const(rb_cGuardTime, "NO_FAILURES", INT2NUM(GT_NO_FAILURES));
	/* The level bytes inside the hash chains are improperly ordered. */
	rb_define_const(rb_cGuardTime, "SYNTACTIC_CHECK_FAILURE", INT2NUM(GT_SYNTACTIC_CHECK_FAILURE));
	/* The hash chain computation result does not match the publication imprint. */	
	rb_define_const(rb_cGuardTime, "HASHCHAIN_VERIFICATION_FAILURE", INT2NUM(GT_HASHCHAIN_VERIFICATION_FAILURE));
	/* The +signed_data+ structure is incorrectly composed, i.e. wrong data
	 * is signed or the signature does not match with the public key in the
	 * timestamp. */
	rb_define_const(rb_cGuardTime, "PUBLIC_KEY_SIGNATURE_FAILURE", INT2NUM(GT_PUBLIC_KEY_SIGNATURE_FAILURE));
	/* Public key of signature token is not found among trusted ones in publications file. */
	rb_define_const(rb_cGuardTime, "NOT_VALID_PUBLIC_KEY_FAILURE", INT2NUM(GT_NOT_VALID_PUBLIC_KEY_FAILURE));
	/* Timestamp does not match with the document it is claimed to belong to. */
	rb_define_const(rb_cGuardTime, "WRONG_DOCUMENT_FAILURE", INT2NUM(GT_WRONG_DOCUMENT_FAILURE));
	 /* The publications file is inconsistent with the corresponding data in
	  * timestamp - publication identifiers do not match or published hash
	  * values do not match.  */
	rb_define_const(rb_cGuardTime, "NOT_VALID_PUBLICATION", INT2NUM(GT_NOT_VALID_PUBLICATION));
}
