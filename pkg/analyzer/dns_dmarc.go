// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
// Authors: Pierre-Olivier Mercier, et al.
//
// This program is offered under a commercial and under the AGPL license.
// For commercial licensing, contact us at <contact@happydomain.org>.
//
// For AGPL licensing:
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package analyzer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

func (d *DNSAnalyzer) checkDMARCRecord(domain string) *api.DMARCRecord {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()
	record := d.lookupDMARCRecord(ctx, domain)
	if record.Record == nil && record.Error == nil {
		record.Error = api.PtrTo("No DMARC record found")
	}
	return record
}

func (d *DNSAnalyzer) domainDMARCRecord(domain string) *api.DMARCRecord {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	exact := d.lookupDMARCRecord(ctx, domain)
	if exact.Record != nil || exact.Error != nil {
		return exact
	}

	// Find a published policy above a name without its own DMARC record.
	// Limit the walk to seven parents, as in the DMARC policy tree walk.
	var inherited *api.DMARCRecord
	var policyDomain string
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	parents := labels[len(labels)-min(len(labels)-1, 7):]
	for i := range parents {
		parent := strings.Join(parents[i:], ".")
		candidate := d.lookupDMARCRecord(ctx, parent)
		if candidate.Record == nil && candidate.Error != nil {
			return candidate
		}
		if !candidate.Valid {
			continue
		}
		psd := dmarcTag(*candidate.Record, "psd")
		if psd == "y" && inherited != nil {
			break
		}
		inherited, policyDomain = candidate, parent
		if psd == "n" || psd == "y" {
			break
		}
	}
	if inherited == nil {
		return &api.DMARCRecord{Error: api.PtrTo("No DMARC record found")}
	}
	inherited.InheritedFrom = &policyDomain
	if inherited.SubdomainPolicy != nil {
		inherited.Policy = api.PtrTo(api.DMARCRecordPolicy(*inherited.SubdomainPolicy))
		inherited.SubdomainPolicy = nil
	}
	return inherited
}

func (d *DNSAnalyzer) lookupDMARCRecord(ctx context.Context, domain string) *api.DMARCRecord {
	txtRecords, err := d.resolver.LookupTXT(ctx, "_dmarc."+strings.TrimSuffix(domain, "."))
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return &api.DMARCRecord{}
		}
		return &api.DMARCRecord{
			Error: api.PtrTo(fmt.Sprintf("Failed to lookup DMARC record: %v", err)),
		}
	}
	var dmarcRecord string
	for _, txt := range txtRecords {
		first, _, _ := strings.Cut(txt, ";")
		if !strings.EqualFold(strings.TrimSpace(first), "v=DMARC1") {
			continue
		}
		if dmarcRecord != "" {
			return &api.DMARCRecord{Error: api.PtrTo("Multiple DMARC records found")}
		}
		dmarcRecord = txt
	}
	if dmarcRecord == "" {
		return &api.DMARCRecord{}
	}

	// Extract policy
	policy := d.extractDMARCPolicy(dmarcRecord)

	// Extract subdomain policy
	subdomainPolicy := d.extractDMARCSubdomainPolicy(dmarcRecord)

	// Extract percentage
	percentage := d.extractDMARCPercentage(dmarcRecord)

	// Extract alignment modes
	spfAlignment := d.extractDMARCSPFAlignment(dmarcRecord)
	dkimAlignment := d.extractDMARCDKIMAlignment(dmarcRecord)

	// Basic validation
	if !d.validateDMARC(dmarcRecord) {
		return &api.DMARCRecord{
			Record:          &dmarcRecord,
			Policy:          api.PtrTo(api.DMARCRecordPolicy(policy)),
			SubdomainPolicy: subdomainPolicy,
			Percentage:      percentage,
			SpfAlignment:    spfAlignment,
			DkimAlignment:   dkimAlignment,
			Valid:           false,
			Error:           api.PtrTo("DMARC record appears malformed"),
		}
	}

	return &api.DMARCRecord{
		Record:          &dmarcRecord,
		Policy:          api.PtrTo(api.DMARCRecordPolicy(policy)),
		SubdomainPolicy: subdomainPolicy,
		Percentage:      percentage,
		SpfAlignment:    spfAlignment,
		DkimAlignment:   dkimAlignment,
		Valid:           true,
	}
}

func dmarcTag(record, key string) string {
	for _, part := range strings.Split(record, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

func (d *DNSAnalyzer) extractDMARCPolicy(record string) string {
	switch policy := dmarcTag(record, "p"); policy {
	case "none", "quarantine", "reject":
		return policy
	default:
		return "unknown"
	}
}

// extractDMARCSPFAlignment extracts SPF alignment mode from a DMARC record
// Returns "relaxed" (default) or "strict"
func (d *DNSAnalyzer) extractDMARCSPFAlignment(record string) *api.DMARCRecordSpfAlignment {
	// Look for aspf=s (strict) or aspf=r (relaxed)
	re := regexp.MustCompile(`aspf=(r|s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		if matches[1] == "s" {
			return api.PtrTo(api.DMARCRecordSpfAlignmentStrict)
		}
		return api.PtrTo(api.DMARCRecordSpfAlignmentRelaxed)
	}
	// Default is relaxed if not specified
	return api.PtrTo(api.DMARCRecordSpfAlignmentRelaxed)
}

// extractDMARCDKIMAlignment extracts DKIM alignment mode from a DMARC record
// Returns "relaxed" (default) or "strict"
func (d *DNSAnalyzer) extractDMARCDKIMAlignment(record string) *api.DMARCRecordDkimAlignment {
	// Look for adkim=s (strict) or adkim=r (relaxed)
	re := regexp.MustCompile(`adkim=(r|s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		if matches[1] == "s" {
			return api.PtrTo(api.DMARCRecordDkimAlignmentStrict)
		}
		return api.PtrTo(api.DMARCRecordDkimAlignmentRelaxed)
	}
	// Default is relaxed if not specified
	return api.PtrTo(api.DMARCRecordDkimAlignmentRelaxed)
}

// extractDMARCSubdomainPolicy extracts subdomain policy from a DMARC record
// Returns the sp tag value or nil if not specified (defaults to main policy)
func (d *DNSAnalyzer) extractDMARCSubdomainPolicy(record string) *api.DMARCRecordSubdomainPolicy {
	switch policy := dmarcTag(record, "sp"); policy {
	case "none", "quarantine", "reject":
		return api.PtrTo(api.DMARCRecordSubdomainPolicy(policy))
	default:
		return nil
	}
}

// extractDMARCPercentage extracts the percentage from a DMARC record
// Returns the pct tag value or nil if not specified (defaults to 100)
func (d *DNSAnalyzer) extractDMARCPercentage(record string) *int {
	// Look for pct=<number>
	re := regexp.MustCompile(`pct=(\d+)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		// Convert string to int
		var pct int
		fmt.Sscanf(matches[1], "%d", &pct)
		// Validate range (0-100)
		if pct >= 0 && pct <= 100 {
			return &pct
		}
	}
	// Default is 100 if not specified
	return nil
}

// validateDMARC performs basic DMARC record validation
func (d *DNSAnalyzer) validateDMARC(record string) bool {
	first, _, _ := strings.Cut(record, ";")
	return strings.EqualFold(strings.TrimSpace(first), "v=DMARC1") && d.extractDMARCPolicy(record) != "unknown"
}

func (d *DNSAnalyzer) calculateDMARCScore(results *api.DNSResults) (score int) {
	// DMARC ties SPF and DKIM together and provides policy
	if results.DmarcRecord != nil {
		if results.DmarcRecord.Valid {
			score += 50
			// Bonus points for stricter policies
			if results.DmarcRecord.Policy != nil {
				switch *results.DmarcRecord.Policy {
				case "reject":
					// Strictest policy - full points already awarded
					score += 25
				case "quarantine":
					// Good policy - no deduction
				case "none":
					// Weakest policy - deduct 5 points
					score -= 25
				}
			}
			// Bonus points for strict alignment modes (2 points each)
			if results.DmarcRecord.SpfAlignment != nil && *results.DmarcRecord.SpfAlignment == api.DMARCRecordSpfAlignmentStrict {
				score += 5
			}
			if results.DmarcRecord.DkimAlignment != nil && *results.DmarcRecord.DkimAlignment == api.DMARCRecordDkimAlignmentStrict {
				score += 5
			}
			// Subdomain policy scoring (sp tag)
			// +3 for stricter or equal subdomain policy, -3 for weaker
			if results.DmarcRecord.SubdomainPolicy != nil {
				mainPolicy := string(*results.DmarcRecord.Policy)
				subPolicy := string(*results.DmarcRecord.SubdomainPolicy)

				// Policy strength: none < quarantine < reject
				policyStrength := map[string]int{"none": 0, "quarantine": 1, "reject": 2}

				mainStrength := policyStrength[mainPolicy]
				subStrength := policyStrength[subPolicy]

				if subStrength >= mainStrength {
					// Subdomain policy is equal or stricter
					score += 15
				} else {
					// Subdomain policy is weaker
					score -= 15
				}
			} else {
				// No sp tag means subdomains inherit main policy (good default)
				score += 15
			}
			// Percentage scoring (pct tag)
			// Apply the percentage on the current score
			if results.DmarcRecord.Percentage != nil {
				pct := *results.DmarcRecord.Percentage

				score = score * pct / 100
			}
		} else if results.DmarcRecord.Record != nil {
			// Partial credit if DMARC record exists but has issues
			score += 20
		}
	}

	return
}
