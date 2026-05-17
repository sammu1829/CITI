const businessPhone = "918074225229";

document.getElementById("orderForm").addEventListener("submit", (event) => {
  event.preventDefault();

  const name = document.getElementById("customerName").value.trim();
  const pickleType = document.getElementById("pickleType").value;
  const quantity = document.getElementById("quantity").value.trim();
  const address = document.getElementById("address").value.trim();

  const message = `Hello CITI Pickles, my name is ${name}. I want to order ${quantity} of ${pickleType}. Delivery area: ${address}. I can pay by PhonePe after confirmation.`;
  const whatsappUrl = `https://wa.me/${businessPhone}?text=${encodeURIComponent(message)}`;

  window.open(whatsappUrl, "_blank", "noopener,noreferrer");
});
