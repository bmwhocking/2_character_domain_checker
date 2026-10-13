use csv::Writer;
use futures::stream::{self, StreamExt};
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Semaphore;
use whois_rust::{WhoIs, WhoIsLookupOptions};

// Struct to hold our output data
#[derive(Debug, Default)]
struct DomainData {
    domain: String,
    registrar: String,
    name_servers: String,
    mx_record: String,
    txt_record: String,
    a_record: String,
    aaaa_record: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Initialize the Async DNS Resolver
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    // 2. Initialize WHOIS client
    // Added the "_" fallback configuration required by whois-rust v3+
    let whois_json = r#"
    {
        "com": {
            "host": "whois.verisign-grs.com",
            "query": "domain $addr\r\n"
        },
        "_": {
            "ip": {
                "host": "whois.arin.net",
                "query": "n + $addr\r\n"
            }
        }
    }"#;
    let whois = Arc::new(WhoIs::from_string(whois_json)?);

    // 3. Setup CSV Writer
    let mut wtr = Writer::from_path("2_letter_domains.csv")?;
    wtr.write_record(&[
        "Domain",
        "Registrar",
        "Name Servers",
        "MX Record",
        "TXT Record",
        "A Record",
        "AAAA Record",
    ])?;

    // Generate all 676 2-letter combinations (aa.com to zz.com)
    let mut domains = Vec::new();
    for c1 in 'a'..='z' {
        for c2 in 'a'..='z' {
            domains.push(format!("{}{}.com", c1, c2));
        }
    }

    // Use a Semaphore to limit concurrent WHOIS lookups
    let semaphore = Arc::new(Semaphore::new(10)); 

    println!("Starting lookups for 676 domains. This may take a few minutes...");

    // 4. Process concurrently
    let mut stream = stream::iter(domains)
        .map(|domain| {
            let resolver = Arc::clone(&resolver);
            let whois = Arc::clone(&whois);
            let permit = Arc::clone(&semaphore);

            tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                let mut data = DomainData {
                    domain: domain.clone(),
                    ..Default::default()
                };

                // A Record
                if let Ok(lookup) = resolver.ipv4_lookup(domain.as_str()).await {
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    data.a_record = ips.join(", ");
                }

                // AAAA Record
                if let Ok(lookup) = resolver.ipv6_lookup(domain.as_str()).await {
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    data.aaaa_record = ips.join(", ");
                }

                // MX Record
                if let Ok(lookup) = resolver.mx_lookup(domain.as_str()).await {
                    let mxs: Vec<String> = lookup.iter().map(|mx| mx.exchange().to_string()).collect();
                    data.mx_record = mxs.join(", ");
                }

                // TX Record
                if let Ok(lookup) = resolver.txt_lookup(domain.as_str()).await {
                    let txts: Vec<String> = lookup
                        .iter()
                        .map(|txt| txt.to_string())
                        .collect();
                    data.txt_record = txts.join(" | ");
                }

                // NS Record
                if let Ok(lookup) = resolver.ns_lookup(domain.as_str()).await {
                    let ns: Vec<String> = lookup.iter().map(|ns| ns.to_string()).collect();
                    data.name_servers = ns.join(", ");
                }

                // WHOIS Lookup (Registrar) using v3.1.0 Async API over the network
                if let Ok(options) = WhoIsLookupOptions::from_string(domain.as_str()) {
                    if let Ok(whois_res) = whois.lookup_async(options).await {
                        for line in whois_res.lines() {
                            if line.to_lowercase().starts_with("registrar:") {
                                data.registrar = line
                                    .split_once(':')
                                    .map(|(_, v)| v.trim().to_string())
                                    .unwrap_or_default();
                                break;
                            }
                        }
                    }
                }
                
                if data.registrar.is_empty() {
                    data.registrar = "Unknown/Hidden".to_string();
                }

                println!("Processed: {}", data.domain);
                data
            })
        })
        .buffer_unordered(10); // Run up to 10 domain lookups simultaneously

    // 5. Write results to CSV as they finish
    while let Some(result) = stream.next().await {
        if let Ok(data) = result {
            wtr.write_record(&[
                data.domain,
                data.registrar,
                data.name_servers,
                data.mx_record,
                data.txt_record,
                data.a_record,
                data.aaaa_record,
            ])?;
        }
    }

    wtr.flush()?;
    println!("Finished! Results saved to 2_letter_domains.csv");

    Ok(())
}
