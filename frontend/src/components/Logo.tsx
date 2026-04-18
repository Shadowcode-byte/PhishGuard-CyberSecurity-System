import { Radar } from "lucide-react";

export default function Logo({ size = 28 }: { size?: number }) {
  return (
    <Radar
      size={size}
      style={{
        color: "#00e5ff",
        filter: "drop-shadow(0 0 10px rgba(0,229,255,0.6))"
      }}
    />
  );
}