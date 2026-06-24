import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex h-10 items-center justify-center gap-2 whitespace-nowrap rounded-md border-0 px-4 text-[15px] font-semibold leading-none transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:bg-secondary disabled:text-white/80 disabled:opacity-70",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-[#f39c12] active:bg-[#d35400]",
        secondary: "bg-secondary text-white hover:bg-[#cacfd2] active:bg-[#a1a6a9]",
        destructive:
          "bg-destructive text-destructive-foreground hover:bg-[#ec7063] active:bg-[#c0392b]",
        outline: "bg-[#bdc3c7] text-white hover:bg-[#cacfd2] active:bg-[#a1a6a9]",
        ghost: "bg-transparent text-foreground hover:bg-muted active:bg-[#d5dbdb]",
      },
      size: {
        default: "h-10 px-4",
        sm: "h-8 px-3 text-sm",
        icon: "h-10 w-10 px-0",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
