/* ScoreRing – SVG circular progress indicator */

interface Props {
  score: number;  // 0-100
  size?: number;
  label?: string;
}

export default function ScoreRing({ score, size = 140, label }: Props) {
  const stroke = 10;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const color =
    score >= 80 ? "var(--success)" :
    score >= 50 ? "var(--warning)" :
    "var(--error)";

  return (
    <div className="score-ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={stroke}
        />
        {/* Progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.6s cubic-bezier(0.4,0,0.2,1)", transformOrigin: "center", transform: "rotate(-90deg)" }}
        />
      </svg>
      <div className="score-ring__inner">
        <span className="score-ring__value" style={{ color }}>{score}%</span>
        {label && <span className="score-ring__label">{label}</span>}
      </div>
    </div>
  );
}
