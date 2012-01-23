#import "X509Cert.h"
#import <openssl/pem.h>
#import <openssl/x509.h>

void ASN1_TYPE_print(BIO *bio,ASN1_TYPE *ptr)
{
	// memory bio to collect the output.
	char objbuf[80];
	const char *ln;
	
	// Collect the things from the ASN1_TYPE structure
	switch(ptr->type)
	{
		case V_ASN1_BOOLEAN:
			BIO_puts(bio, ptr->value.boolean ? "true" : "false");
			break;
			
		case V_ASN1_INTEGER:
			BIO_puts(bio,i2s_ASN1_INTEGER(NULL,ptr->value.integer));
			break;
			
		case V_ASN1_ENUMERATED:
			BIO_puts(bio,i2s_ASN1_INTEGER(NULL,ptr->value.enumerated));
			break;
			
		case V_ASN1_NULL:
			BIO_puts(bio,"none");
			break;
			
		case V_ASN1_UTCTIME:
			ASN1_UTCTIME_print(bio,ptr->value.utctime);
			break;
			
		case V_ASN1_GENERALIZEDTIME:
			ASN1_GENERALIZEDTIME_print(bio,ptr->value.generalizedtime);
			break;
			
		case V_ASN1_OBJECT:
			ln = OBJ_nid2ln(OBJ_obj2nid(ptr->value.object));
			if( !ln ) ln = "";
			OBJ_obj2txt(objbuf,sizeof(objbuf),ptr->value.object,1);
			BIO_puts(bio,objbuf);
			break;
			
		default :
			ASN1_STRING_print_ex(bio, ptr->value.visiblestring,
								 ASN1_STRFLGS_DUMP_UNKNOWN|ASN1_STRFLGS_SHOW_TYPE);
			break;
	}
	
}


NSString * md5(X509 *x)
{
	const EVP_MD *digest = EVP_md5();
	unsigned int digestLen;
	unsigned char md[EVP_MAX_MD_SIZE];
	int res=X509_digest(x,digest,md,&digestLen);
	if(!res)
	{
		return nil;
	}
	BIO *bio = BIO_new(BIO_s_mem());	
	for (int i=0; i<(int)digestLen; i++)
	{
		BIO_printf(bio,"%02X%c",md[i],(i+1 == (int)digestLen)?'\n':':');
	}
	
	unsigned char *data,*result;
	int n = BIO_get_mem_data(bio, &data);
	result = (unsigned char *) malloc (n+1);
	result[n]='\0';
	memcpy(result,data,n);
	
	BIO_free(bio);
	bio=NULL;
	return [[NSString alloc] initWithCString:result
									encoding:NSASCIIStringEncoding];		
}

NSString * sha1(X509 *x)
{
	const EVP_MD *digest = EVP_sha1();
	unsigned int digestLen;
	unsigned char md[EVP_MAX_MD_SIZE];
	int res=X509_digest(x,digest,md,&digestLen);
	if(!res)
	{
		return nil;
	}
	BIO *bio = BIO_new(BIO_s_mem());	
	for (int i=0; i<(int)digestLen; i++)
	{
		BIO_printf(bio,"%02X%c",md[i],(i+1 == (int)digestLen)?'\n':':');
	}
	
	unsigned char *data,*result;
	int n = BIO_get_mem_data(bio, &data);
	result = (unsigned char *) malloc (n+1);
	result[n]='\0';
	memcpy(result,data,n);
	
	BIO_free(bio);
	bio=NULL;
	return [[NSString alloc] initWithCString:result
									encoding:NSASCIIStringEncoding];		
}
NSString * _decStr(BIGNUM *bn)
{
	unsigned char *result;
	result = BN_bn2dec(bn);				
	
	return [[NSString alloc] initWithCString:result 
									encoding:NSASCIIStringEncoding];		
}
NSString * _hexStr(BIGNUM *bn)
{
	unsigned char *result;
	result = BN_bn2hex(bn);				
	
	return [[NSString alloc] initWithCString:result 
									encoding:NSASCIIStringEncoding];	
}
NSString * hexStr(ASN1_INTEGER *value)
{
	BIGNUM *bn = NULL;
	bn = ASN1_INTEGER_to_BN(value,NULL);
	
	return _hexStr(bn);
}

NSString *typeStr(ASN1_TYPE *type)
{
	unsigned char *data,*result;
	BIO *bio = BIO_new(BIO_s_mem());	
	ASN1_TYPE_print(bio,type);
	
	int n = BIO_get_mem_data(bio, &data);
	result = (unsigned char *) malloc (n+1);
	result[n]='\0';
	memcpy(result,data,n);	
	
	BIO_free(bio);	
	bio=NULL;
	NSString *str=[[NSString alloc] initWithCString:result 
										   encoding:NSASCIIStringEncoding];		
	return [str stringByReplacingOccurrencesOfString:@"SEQUENCE:#" withString:@""];
}

NSString * objStr(ASN1_OBJECT *obj)
{
	unsigned char *data,*result;
	BIO *bio = BIO_new(BIO_s_mem());	
	int len=i2a_ASN1_OBJECT(bio,obj);
	
	int n = BIO_get_mem_data(bio, &data);
	result = (unsigned char *) malloc (n+1);
	result[n]='\0';
	memcpy(result,data,n);	
	
	BIO_free(bio);	
	bio=NULL;
	return [[NSString alloc] initWithCString:result 
									encoding:NSASCIIStringEncoding];
	
}

NSString * str(X509_NAME *name)
{
	unsigned char *data,*result;
	BIO *bio = BIO_new(BIO_s_mem());	
	X509_NAME_print_ex(bio,name, 0,0);
	
	int n = BIO_get_mem_data(bio, &data);
	result = (unsigned char *) malloc (n+1);
	result[n]='\0';
	memcpy(result,data,n);	
	
	BIO_free(bio);	
	bio=NULL;
	return [[NSString alloc] initWithCString:result 
									encoding:NSASCIIStringEncoding];
}

NSString * _str(ASN1_STRING *name)
{
	unsigned char *data,*result;
	BIO *bio = BIO_new(BIO_s_mem());	
	ASN1_STRING_print(bio, name);
	
	int n = BIO_get_mem_data(bio, &data);
	result = (unsigned char *) malloc (n+1);
	result[n]='\0';
	memcpy(result,data,n);	
	
	BIO_free(bio);	
	bio=NULL;
	return [[NSString alloc] initWithCString:result 
									encoding:NSASCIIStringEncoding];
}


NSDate * date(ASN1_TIME *value)
{
	unsigned char *data,*result;
	BIO *bio = BIO_new(BIO_s_mem());	
	ASN1_TIME_print(bio,value);
	
	int n = BIO_get_mem_data(bio, &data);
	result = (unsigned char *) malloc (n+1);
	result[n]='\0';
	memcpy(result,data,n);	
	
	NSString *date=[[NSString alloc] initWithCString:result 
											encoding:NSASCIIStringEncoding];
	//Jan 21 10:20:56 2010 GMT
	NSDateFormatter *format=[[NSDateFormatter alloc] init];
	[format setFormatterBehavior: NSDateFormatterBehavior10_0];
	
	[format setDateFormat:@"%b %d %H:%M:%S %Y %Z"];
	
	NSDate *cdate=[format dateFromString:date];
	
	[format release];
	[date release];
	BIO_free(bio);	
	bio=NULL;
	
	return cdate;
}

@implementation X509Cert
@synthesize key,issuer,subject,serial,issueDate,expiryDate,isParsed,md5Digest,sha1Digest,version,sigAlgo,sigParams;
-(id) initWithURL:(NSURL *)url
{
	self = [super init];
	if (self != nil) 
	{	
		[self initIndicies];
		[self tryPEM:url];
		if(!self.isParsed) 
			[self tryDER:url];
	}
	return self;	
}

- (void) tryPEM:(NSURL *)url
{
	X509 *x;
	FILE *fp;
	
	if ((fp=fopen([[url path] cStringUsingEncoding:NSASCIIStringEncoding],"r")) != NULL)	
	{
		x=X509_new();
		if (PEM_read_X509(fp,&x,NULL,NULL)!=NULL)
		{				
			[self extractData:x];			
			isParsed=YES;
		}		
		fclose(fp);
	}
}

- (void) tryDER:(NSURL *)url
{
	X509 *x;
	FILE *fp;
	
	if ((fp=fopen([[url path] cStringUsingEncoding:NSASCIIStringEncoding],"r")) != NULL)	
	{
		x=X509_new();
		if (d2i_X509_fp(fp,&x)!=NULL)
		{				
			[self extractData:x];			
			isParsed=YES;
		}		
		fclose(fp);
	}	
}


- (void)extractData:(X509 *)x
{
	sigAlgo=objStr(x->sig_alg->algorithm);		
	sigParams=typeStr(x->sig_alg->parameter);
	
	self.issuer=str(X509_get_issuer_name(x));
	self.subject=str(X509_get_subject_name(x));
	self.serial=hexStr(X509_get_serialNumber(x));
	self.version=X509_get_version(x);
	self.version++;
	self.issueDate=date(X509_get_notBefore(x));
	self.expiryDate=date(X509_get_notAfter(x));	
	self.md5Digest=md5(x);
	self.sha1Digest=sha1(x);
	
	self.key=[[PubKey alloc] init];
	self.key.algo=objStr(x->cert_info->key->algor->algorithm);
	self.key.params=typeStr(x->cert_info->key->algor->parameter);
	
	EVP_PKEY *pkey=X509_get_pubkey(x);
	if (pkey->type == EVP_PKEY_RSA)
	{
		self.key.keyMaterial=_hexStr(pkey->pkey.rsa->n);
		self.key.exponent=_decStr(pkey->pkey.rsa->e);
		self.key.keySize=[NSString stringWithFormat:@"%i",BN_num_bits(pkey->pkey.rsa->n)];		
	}
	
	else if(pkey->type == EVP_PKEY_DSA)
	{
		self.key.keyMaterial=_hexStr(pkey->pkey.dsa->pub_key);
		self.key.keySize=[NSString stringWithFormat:@"%i",BN_num_bits(pkey->pkey.dsa->pub_key)];
	}
	
	
	
	EVP_PKEY_free(pkey);
	
}
- (NSString *)colonSeparatedSerial
{
	NSMutableString *str=[[NSMutableString alloc] initWithString:self.serial];
	
	for(int i=[str length]-2;i>=2;i-=2)
	{
		[str insertString:@":"atIndex:i];
	}
	
	return str;
}

- (BOOL) isExpired
{
	NSComparisonResult res=[expiryDate compare:[NSDate date]];
	return res!=NSOrderedDescending;
}

- (int) daysBeforeExpiration
{
	return [expiryDate timeIntervalSinceDate:[NSDate date]]/(60*60*24);
}

- (NSString *)pubKeyAlgoWithOid
{
	NSString *displayName=[lnToDisplayName objectForKey:key.algo];
	NSString *displayOid=[lnToDisplayOid objectForKey:key.algo];
	
	if(displayOid==nil)
		displayOid=key.algo;
	
	if(displayName==nil)
		displayName=key.algo;
	
	return [NSString stringWithFormat:@"%@ ( %@ )",
			displayName,displayOid];	
}

- (NSString *)algoWithOid
{
	NSString *displayName=[lnToDisplayName objectForKey:sigAlgo];
	NSString *displayOid=[lnToDisplayOid objectForKey:sigAlgo];
	
	if(displayOid==nil)
		displayOid=sigAlgo;
	
	if(displayName==nil)
		displayName=sigAlgo;
	
	return [NSString stringWithFormat:@"%@ ( %@ )",
			displayName,displayOid];
}

- (NSString *)formatedIssueDate
{	
	NSDateFormatter *format = [[[NSDateFormatter alloc]
								initWithDateFormat:@"%A, %B %d %Y, %H:%M %z(%Z)" allowNaturalLanguage:NO] autorelease];
	return [format stringFromDate:issueDate];
}

- (NSString *)formatedExpiryDate
{
	NSDateFormatter *format = [[[NSDateFormatter alloc]
								initWithDateFormat:@"%A, %B %d %Y, %H:%M %z(%Z)" allowNaturalLanguage:NO] autorelease];
	return [format stringFromDate:expiryDate];
}

- (void)initIndicies
{
	lnToDisplayOid=[[NSDictionary alloc] initWithObjectsAndKeys:
					@"1 2 840 10040 4 3",@"dsaWithSHA1",
					@"1 2 840 10040 4 1", @"dsaEncryption",
					@"1 2 840 113549 1 1 1",@"rsaEncryption",
					@"1 2 840 113549 1 1 2",@"md2WithRSAEncryption",
					@"1 2 840 113549 1 1 4",@"md5WithRSAEncryption",
					@"1 2 840 113549 1 1 5",@"sha1WithRSAEncryption",
					nil];
	
	lnToDisplayName=[[NSDictionary alloc] initWithObjectsAndKeys:
  					 @"DSA with SHA-1", @"dsaWithSHA1",					 
 					 @"DSA", @"dsaEncryption",					 
					 @"RSA Encryption",@"rsaEncryption",
					 @"MD-2 with RSA Encryption",@"md2WithRSAEncryption",
					 @"MD-5 with RSA Encryption",@"md5WithRSAEncryption",
					 @"SHA-1 with RSA Encryption",@"sha1WithRSAEncryption",					 
					 nil];
}

@end
