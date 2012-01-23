#import <Cocoa/Cocoa.h>


@interface PubKey : NSObject 
{
	NSString *algo;
	NSString *params;
	NSString *keyMaterial;
	NSString *keySize;
	NSString *signature;
	NSString *keyUsage;
	NSString *exponent;		
}

@property(readwrite,assign)NSString *algo;
@property(readwrite,assign)NSString *params;
@property(readwrite,assign)NSString *keyMaterial;
@property(readwrite,assign)NSString *keySize;
@property(readwrite,assign)NSString *signature;
@property(readwrite,assign)NSString *keyUsage;
@property(readwrite,assign)NSString *exponent;
@end
