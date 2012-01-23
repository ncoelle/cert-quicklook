#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <QuickLook/QuickLook.h>
#include <Cocoa/Cocoa.h>
#include "X509Cert.h"

void render(NSMutableString *template,NSDictionary *data)
{
	for (NSString *key in [data allKeys]) 
	{
		NSString *pattern=[NSString stringWithFormat:@"${%@}",key];
		NSString *value=[data objectForKey:key];
		
		if(value==nil)
			value=@"";
		
		[template replaceOccurrencesOfString:pattern
								  withString:value
									 options:NSLiteralSearch
									   range:NSMakeRange(0, [template length])];			
	}
}

OSStatus GeneratePreviewForURL(void *thisInterface, QLPreviewRequestRef preview, CFURLRef url, CFStringRef contentTypeUTI, CFDictionaryRef options)
{
	NSAutoreleasePool *pool;
	
    pool = [[NSAutoreleasePool alloc] init];
	
    if (QLPreviewRequestIsCancelled(preview))
        return noErr;
	
	X509Cert *cert=[[X509Cert alloc] initWithURL:url];
	
	NSMutableDictionary *props=[[[NSMutableDictionary alloc] init] autorelease];
	[props setObject:@"UTF-8" forKey:(NSString *)kQLPreviewPropertyTextEncodingNameKey];
	[props setObject:@"text/html" forKey:(NSString *)kQLPreviewPropertyMIMETypeKey];
		
	NSString *templatePath=[NSString stringWithFormat:@"%@%@",
							[[NSBundle bundleWithIdentifier:@"com.pingidentity.qlgenerator.x509"] bundlePath], 
							@"/Contents/Resources/index.html"];

	NSString *resourcePath=[NSString stringWithFormat:@"%@%@",
							[[NSBundle bundleWithIdentifier:@"com.pingidentity.qlgenerator.x509"] bundlePath], 
							@"/Contents/Resources"];
	
	NSMutableString *template=[NSMutableString stringWithContentsOfFile:templatePath 
												encoding:NSUTF8StringEncoding
												   error:nil];
		
	NSMutableDictionary *data=[[[NSMutableDictionary alloc] init] autorelease];
	[data setObject:resourcePath forKey:@"resourcePath"];
	[data setObject:cert.subject forKey:@"subject"];
	[data setObject:cert.issuer forKey:@"issuer"];	
	[data setObject:[cert formatedIssueDate] forKey:@"issue-date"];	
	[data setObject:[cert formatedExpiryDate] forKey:@"expiry-date"];		
	[data setObject:[cert colonSeparatedSerial] forKey:@"serial"];		
	[data setObject:cert.md5Digest forKey:@"fingerprint-md5"];
	[data setObject:cert.sha1Digest forKey:@"fingerprint-sha1"];	
	[data setObject:[cert algoWithOid] forKey:@"algoWithOid"];
	[data setObject:cert.sigParams forKey:@"sigParams"];	
	[data setObject:[NSString stringWithFormat:@"%i",cert.version] forKey:@"version"];
	
	//pubkey info
	[data setObject:[cert pubKeyAlgoWithOid] forKey:@"pubkey-algo"];	
	[data setObject:[cert.key spaceSeparated:cert.key.params] forKey:@"pubkey-params"];	
	[data setObject:[cert.key previewParams] forKey:@"pubkey-params-preview"];	
	
	[data setObject:[cert.key spaceSeparatedMaterial] forKey:@"pubkey-material"];	
	[data setObject:[cert.key previewMaterial] forKey:@"pubkey-material-preview"];		
	if(cert.key.exponent!=nil)
	{
		[data setObject:cert.key.exponent forKey:@"pubkey-exponent"];	
		[data setObject:@"" forKey:@"show-exponent"];		
	}		
	else
		[data setObject:@"dontShow" forKey:@"show-exponent"];
	
	[data setObject:cert.key.keySize forKey:@"pubkey-size"];	
	
	if([cert isExpired])
	{
		[data setObject:@"expired" forKey:@"expiry-css"];				
		[data setObject:@"Expired!" forKey:@"expiry-days-left"];
	}
	else
	{
		NSString *msg=[NSString stringWithFormat:@"%i days left.",[cert daysBeforeExpiration]];
		[data setObject:@"valid" forKey:@"expiry-css"];				
		[data setObject:msg forKey:@"expiry-days-left"];		
	}
	
	render(template,data);
	
	QLPreviewRequestSetDataRepresentation(preview,
										  (CFDataRef)[template dataUsingEncoding:NSUTF8StringEncoding],
										  kUTTypeHTML,(CFDictionaryRef)props);
//	[template release];
//	[templatePath release];
    [pool release];
	return noErr;
}

void CancelPreviewGeneration(void* thisInterface, QLPreviewRequestRef preview)
{
    // implement only if supported
}
