package elasticsearch

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	es7 "github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// clusterInfo holds information about an ElasticSearch cluster.
type clusterInfo struct {
	ClusterName   string
	ServerVersion string
	ClientVersion string
}

// parseInfo parses an *esapi.Response and returns a clusterInfo.
func parseInfo(res *esapi.Response) (*clusterInfo, error) {

	// Check response status.
	if res.IsError() {
		return nil, fmt.Errorf("error getting cluster info: %s", res)
	}

	// Deserialize the response into a map.
	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return nil, errors.Wrap(err, "error parsing info response body")
	}

	// Print client and server version numbers.
	return &clusterInfo{
		ClusterName:   r["cluster_name"].(string),
		ServerVersion: r["version"].(map[string]interface{})["number"].(string),
		ClientVersion: es7.Version,
	}, nil
}
