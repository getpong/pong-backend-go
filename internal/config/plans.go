package config

// PlanLimits defines the resource limits for a subscription plan.
// A value of -1 means unlimited.
type PlanLimits struct {
	MaxMonitors int // max number of monitors
	MinInterval int // minimum check interval in seconds
	MaxContacts int // max number of alert contacts
}

var Plans = map[string]PlanLimits{
	"free":       {MaxMonitors: 25, MinInterval: 300, MaxContacts: 3},
	"pro":        {MaxMonitors: 100, MinInterval: 60, MaxContacts: 25},
	"business":   {MaxMonitors: 500, MinInterval: 30, MaxContacts: -1},
	"selfhosted": {MaxMonitors: -1, MinInterval: 1, MaxContacts: -1},
}

// GetPlanLimits returns the limits for a plan. Defaults to free if unknown.
func GetPlanLimits(plan string) PlanLimits {
	if l, ok := Plans[plan]; ok {
		return l
	}
	return Plans["free"]
}
