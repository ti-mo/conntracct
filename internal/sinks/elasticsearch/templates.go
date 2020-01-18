package elasticsearch

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// installMappings sets up data types for exported fields.
// An index template 'conntracct_mappings.<db>' is installed on
// the elasticsearch server for the given db prefix.
func (s *ElasticSink) installMappings(db string) error {

	// Name of the installed index template.
	templateName := fmt.Sprintf("conntracct_mappings.%s", db)

	mappings := fmt.Sprintf(`{
		"index_patterns" : ["%s-*"],
		"order": 0,
		"mappings":{
			"properties":{
				"bytes_orig": { "type":"long" },
				"bytes_ret": { "type":"long" },
				"bytes_total": { "type":"long" }, // Calculated field.
				"packets_orig": { "type":"long" },
				"packets_ret": { "type":"long" },
				"packets_total": { "type":"long" }, // Calculated field.
				"flow_id": { "type":"long" },
				"connmark": { "type":"integer" },
				"src_addr": { "type":"ip" },
				"src_port": { "type":"integer" },
				"dst_addr": { "type":"ip" },
				"dst_port": { "type":"integer" },
				"netns": { "type":"long" },
				// Using normal (millisecond) date instead of date_nanos.
				// Nanosecond-resolution unix timestamps cannot be ingested.
				// https://github.com/elastic/elasticsearch/issues/43917
				"start": { "type":"date" },
				"timestamp": { "type":"date" }
			}
		}
	}`, db)

	return s.installTemplate(templateName, mappings)
}

// installSettings applies shard and replication configuration for conntracct indices.
// An index template 'conntracct_settings.<db>' is installed on
// the elasticsearch server for the given db prefix.
func (s *ElasticSink) installSettings(db string, shards, replicas uint16) error {

	// Name of the installed index template.
	templateName := fmt.Sprintf("conntracct_settings.%s", db)

	settings := fmt.Sprintf(`{
		"index_patterns" : ["%s-*"],
		"order": 0,
		"settings": {
			"number_of_shards": %d,
			"number_of_replicas": %d
		}
	}`, db, shards, replicas)

	return s.installTemplate(templateName, settings)
}

// installTemplate applies the given template name and body
// to the elasticsearch server.
func (s *ElasticSink) installTemplate(name, body string) error {

	resp, err := s.client.IndexPutTemplate(name).BodyJson(body).Do(context.Background())
	if err != nil {
		return err
	}

	if !resp.Acknowledged {
		return errIndexTemplate
	}

	log.WithField("sink", s.config.Name).Debugf("Installed '%s' index template", name)

	return nil
}
