#import <Cocoa/Cocoa.h>
#import "PubKey.h"

@interface X509Cert : NSObject 
{
	NSString *serial;
	NSString *issuer;
	NSString *subject;
	NSDate *issueDate;
	NSDate *expiryDate;	
	NSString *md5Digest;
	NSString *sha1Digest;	
	NSString *sigAlgo;
	NSString *sigParams;
	long version;
	
	BOOL isParsed;
	
	NSDictionary *lnToDisplayName;
	NSDictionary *lnToDisplayOid;
	
	PubKey *key;
}
@property(readwrite)long version;
@property(readwrite,assign)NSString *sigParams;
@property(readwrite,assign)PubKey *key;
@property(readwrite,assign)NSString *sigAlgo;
@property(readwrite,assign)NSString *md5Digest;
@property(readwrite,assign)NSString *sha1Digest;
@property(readwrite,assign)NSString *serial;
@property(readwrite,assign)NSString *issuer;
@property(readwrite,assign)NSString *subject;
@property(readwrite,assign)NSDate *issueDate;
@property(readwrite,assign)NSDate *expiryDate;
@property(readwrite)BOOL isParsed;

- (id) initWithURL:(NSURL *)url;
- (NSString *)colonSeparatedSerial;
- (BOOL) isExpired;
- (int) daysBeforeExpiration;
- (NSString *)formatedIssueDate;
- (NSString *)formatedExpiryDate;
- (NSString *)algoWithOid;
@end
