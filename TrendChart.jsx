// frontend/src/components/TrendChart.jsx
import {
  Chart as ChartJS,
  LineElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Legend,
  Tooltip
} from "chart.js";
import { Line } from "react-chartjs-2";

ChartJS.register(
  LineElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Legend,
  Tooltip
);

export default function TrendChart({ title, labels, datasets }) {
  const data = {
    labels,
    datasets
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top"
      }
    },
    scales: {
      x: {
        ticks: {
          maxTicksLimit: 8
        }
      }
    }
  };

  return (
    <div className="card wide" style={{ height: 350 }}>
      <h3 style={{ marginBottom: 10 }}>{title}</h3>
      <Line data={data} options={options} />
    </div>
  );
}
