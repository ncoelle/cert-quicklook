#import "PubKey.h"

@implementation PubKey
@synthesize algo,params,exponent,keySize,keyMaterial,signature,keyUsage;

- (long) paramsSize
{
	return [self.params length]/2;
}

- (NSString *)previewMaterial
{
	NSString *material=[self spaceSeparatedMaterial];
	if(material==nil || [material length] < 23)
		return [NSString stringWithFormat:@"%i bytes : %@",
							[self.keyMaterial length]/2,material]; 
	else
		return [NSString stringWithFormat:@"%i bytes : %@ ...",
				[self.keyMaterial length]/2,[material substringToIndex:23]]; 
}

- (NSString *)previewParams
{
	if([self.params isEqualToString:@"none"])
		return self.params;

	NSString *params=[self spaceSeparated:self.params];
	if(params==nil || [params length] < 23)
		return [NSString stringWithFormat:@"%i bytes : %@",
				[self.params length]/2, params]; 
	else
		return [NSString stringWithFormat:@"%i bytes : %@ ...",
				[self.params length]/2,[params substringToIndex:23]]; 	
}

- (NSString *)spaceSeparatedMaterial
{
	return [self spaceSeparated:self.keyMaterial];
}

- (NSString *)spaceSeparated:(NSString *)input
{
	if(input==nil || [input isEqualToString:@"none"]) 
		return input;
	
	NSMutableString *str=[[NSMutableString alloc] initWithString:input];
	
	for(int i=[str length]-2;i>=2;i-=2)
	{
		[str insertString:@" "atIndex:i];
	}
	
	return str;	
}

@end
