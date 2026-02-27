export default function SensorCard({
    title,
    iconClass,
    value,
    unit = "",
    min,
    max
}) 

{
    const isNumber = typeof value === "number" && Number.isFinite(value);
    const ok = isNumber && value >= min && value <= max;

    return (
    <div className="card" data-min={min} data-max={max}>
        <div className="card-header">
            <span>{title}</span>
            <i className={iconClass}></i>
        </div>

        <div className="value">
            {isNumber ? `${value}${unit}` : "--"}
        </div>

        <div className="footer">
            <span className="range">Range: {min} - {max}</span>
            <span className={`status ${isNumber ? (ok ? "ok" : "warning") : ""}`}>
                {isNumber ? (ok ? "OK" : "Warning") : ""}
            </span>
        </div>
    </div>
    );
}
