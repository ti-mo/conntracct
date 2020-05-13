package elasticsearch

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
)

var (
	// Name of the flow upsert script on the elastic server.
	scriptFlowUpsertName = "ct-flow-upsert"

	// Scripted upsert. Only commit a document update to the index if the
	// document does not yet exist on the server, or if its state is
	// 'established'. This is to prevent out-of-order destroys being clobbered
	// by updates. Once a document has a flow_state 'finished', it's immutable.
	scriptFlowUpsert = `if (ctx._source.flow_state == null || ctx._source.flow_state == 'established') {
		ctx._source = params.doc;
	} else {
		ctx.op = 'none';
	}`
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
				"flow_id": { "type":"keyword" },
				"bytes_orig": { "type":"long" },
				"bytes_ret": { "type":"long" },
				"bytes_total": { "type":"long" }, // Calculated field.
				"packets_orig": { "type":"long" },
				"packets_ret": { "type":"long" },
				"packets_total": { "type":"long" }, // Calculated field.
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

// installScript installs the named Painless script to the elastic server.
func (s *ElasticSink) installScript(name, source string) error {

	script := fmt.Sprintf(`{
		"script": {
			"lang": "painless",
			"source": "%s"
		}
	}`, mustJSONEscape(source))

	resp, err := s.client.PutScript().Id(name).BodyString(script).Do(context.Background())
	if err != nil {
		return err
	}

	if !resp.Acknowledged {
		return errScript
	}

	log.WithField("sink", s.config.Name).Debugf("Installed stored script '%s'", name)

	return nil
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
