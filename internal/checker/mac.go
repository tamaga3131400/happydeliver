package checker

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

func macLookup(_ context.Context, q url.Values) (*Result, error) {
	input := strings.TrimSpace(q.Get("q"))
	mac, ok := macValue(input)
	if !ok {
		return nil, fail("Please enter a MAC address such as 00:1A:2B:3C:4D:5E or its first six digits.",
			"Bitte gib eine MAC-Adresse wie 00:1A:2B:3C:4D:5E oder ihre ersten sechs Stellen ein.")
	}
	table := macVendors.Load()
	if table == nil {
		return nil, fail("The vendor list is being loaded. Please try again in a few minutes.",
			"Die Herstellerliste wird gerade geladen. Bitte versuche es in ein paar Minuten erneut.")
	}
	first := byte(mac >> 40)
	octets := make([]string, 6)
	for i := range octets {
		octets[i] = fmt.Sprintf("%02X", byte(mac>>(40-8*i)))
	}
	section := Section{Title: T("MAC address", "MAC-Adresse"), Rows: []Row{row("Address", "Adresse", strings.Join(octets, ":"))}}
	vendor, bits := table.lookup(mac)
	switch {
	case first&0x02 != 0:
		section.Rows = append(section.Rows, noteRow("Vendor", "Hersteller",
			"none – locally administered address (e.g. a randomised MAC of a phone or virtual machine)",
			"keiner – lokal vergebene Adresse (z. B. zufällige MAC eines Smartphones oder einer VM)", "warn"))
	case vendor != "":
		section.Rows = append(section.Rows, row("Vendor", "Hersteller", vendor, "ok"),
			row("Matched prefix", "Passendes Präfix", fmt.Sprintf("%d bit", bits)))
	default:
		section.Rows = append(section.Rows, noteRow("Vendor", "Hersteller", "not registered", "nicht registriert", "warn"))
	}
	kind := Text{"unicast", "Unicast"}
	if first&0x01 != 0 {
		kind = Text{"multicast / group address", "Multicast / Gruppenadresse"}
	}
	section.Rows = append(section.Rows, Row{Label: T("Type", "Art"), Note: &kind})
	return &Result{Sections: []Section{section}}, nil
}
