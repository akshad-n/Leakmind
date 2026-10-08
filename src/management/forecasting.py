"""
Risk Forecasting & Trend Projection Engine
Projects user risk velocity and future leak probability across rolling horizons.
"""

from typing import Any, Dict, List
import numpy as np


class RiskForecastingEngine:
    """
    Computes risk trajectory, velocity (rate of risk escalation), and forecasts future risk scores.
    """

    def forecast_risk_trajectory(
        self,
        historical_scores: List[float],
        forecast_horizon_days: int = 7
    ) -> Dict[str, Any]:
        if not historical_scores:
            return {
                "current_risk": 0.0,
                "projected_risk": 0.0,
                "velocity": "STABLE",
                "trend_slope": 0.0
            }

        if len(historical_scores) == 1:
            return {
                "current_risk": historical_scores[0],
                "projected_risk": historical_scores[0],
                "velocity": "STABLE",
                "trend_slope": 0.0
            }

        x = np.arange(len(historical_scores))
        y = np.array(historical_scores)

        # Simple linear trend fitting
        slope, intercept = np.polyfit(x, y, 1)

        projected = slope * (len(historical_scores) - 1 + forecast_horizon_days) + intercept
        projected = min(100.0, max(0.0, float(projected)))

        if slope > 2.0:
            velocity = "ACCELERATING_CRITICAL"
        elif slope > 0.5:
            velocity = "INCREASING"
        elif slope < -0.5:
            velocity = "DECREASING"
        else:
            velocity = "STABLE"

        return {
            "current_risk": round(historical_scores[-1], 2),
            "projected_risk": round(projected, 2),
            "velocity": velocity,
            "trend_slope": round(float(slope), 4),
            "horizon_days": forecast_horizon_days
        }
