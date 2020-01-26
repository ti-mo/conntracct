# Elasticsearch

The main goal of storing flow data in elasticsearch is creating historical records.
Elastic allows for a data set to grow larger than a single-instance Prometheus or InfluxDB
would realistically be able to store. However, there are a few caveats.

At the time of writing (elasticsearch version 7.5.1), there seem to be some feature gaps
in both the database as well as the visualization tooling itself (Kibana and Grafana).

## Notes on building bandwidth graphs in Kibana/Grafana

Due to the nature of flow tracking, the amount of time series is highly variable. Every time
a new flow is created, updated or destroyed, a document with the flow's `flow_id` and its counters
is logged. To obtain the current state of a flow at any point in time, we can either request the
most recent document of that flow, or the document with the highest `bytes/packets_total` value,
depending on the aggregation types available at that point in the pipeline.

In the elastic query engine, this can be done using a 'Terms Aggregation' on `flow_id`.
Essentially, this creates a bucket for each distinct value of `flow_id` that holds all documents
belonging to that flow. Then, the document with the highest `bytes_total` value is picked and used
as the resulting calculated value for that bucket.

Next in the pipeline is the (confusingly-named) 'Date Histogram' aggregation to visualize a time
series over a specified time range. This aggregation also buckets the data, resulting in one bucket
per (for example) 5 minutes, resulting in a nested structure. Each date bucket now contains one bucket
for each `flow_id`; at least the configured top or bottom N flows.

Up until here, our use case seems fairly standard. Beyond that, some limitations become apparent:

- The `flow_id` Terms Aggregation is limited to a maximum amount of buckets. While this can be set
  to a very high number, there's a chance for larger deployments to ignore flows that fall
  outside this aggregation limit. Also, the database needs to be reconfigured to increase the
  10k bucket limit per query.
- The `Derivative` aggregation yields the delta value between consecutive buckets, not the rate of
  change. This value can be negative and is not suited for calculating bandwidth.
- `Derivative` operates over buckets, not individual documents, causing large discrepancies
  between the actual flow rate and the queried result. This effect gets worse as the date bucket
  size gets bigger.
- `Derivative` does not normalize the delta to the step size of the buckets, eg. values are not
  converted to per-second rates. This can be achieved by setting `{ "unit": "second" }` on the
  Derivative's JSON Input. However, this yields an extra `normalized_value` field in the response,
  leaving the original `value` untouched. Kibana ignores this `normalized_value` field and I have
  not found a way to make it visualize it instead of the original `value`.
- Timelion's `.derivative()` is closer to what we need and can visualize rate of change. However,
  neither Timelion nor TSVB have an equivalent to a 'Sum Bucket' aggregation. For example, once
  bucketed per `flow_id`, data cannot be summed back to a single bucket per time bucket.
- In Timelion's `.es(split=flow_id:N)` parameter, N cannot be set to 0 to sum all flows in the time
  range, limiting calculations to the top N flows. Also, this method seems to exceed the default 10k
  bucket query limit at about 100 flows.

Long story short, after spending the bigger part of 2 days experimenting with the various visualizations
and query builders (Area, Timelion and TSVB alike), I've come to the conclusion that other tools
would be better suited for drawing graphs.
