module github.com/ninsun-labs/ugallu/resolver

go 1.26.2

require (
	github.com/ninsun-labs/ugallu/sdk v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.72.2
)

require (
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
)

replace github.com/ninsun-labs/ugallu/sdk => ../sdk
